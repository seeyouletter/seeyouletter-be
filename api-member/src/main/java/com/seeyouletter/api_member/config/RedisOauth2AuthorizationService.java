package com.seeyouletter.api_member.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeyouletter.api_member.auth.config.CustomAuthorization;
import com.seeyouletter.api_member.auth.config.CustomAuthorization.CustomAuthorizationBuilder;
import com.seeyouletter.api_member.auth.config.CustomAuthorizationMixIn;
import com.seeyouletter.api_member.auth.config.CustomOAuth2User;
import com.seeyouletter.api_member.auth.config.CustomOauth2UserMixIn;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.data.redis.connection.RedisStringCommands;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization.Token;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.util.Assert;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.security.MessageDigest.getInstance;
import static java.time.temporal.ChronoUnit.MINUTES;
import static org.springframework.data.redis.connection.RedisStringCommands.SetOption.UPSERT;
import static org.springframework.data.redis.core.types.Expiration.from;
import static org.springframework.security.jackson2.SecurityJackson2Modules.getModules;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.INVALID_REQUEST;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN;
import static org.springframework.util.StringUtils.hasText;

public final class RedisOauth2AuthorizationService implements OAuth2AuthorizationService {

    private static final Duration AUTHORIZATION_CONSENT_TIME_LIMIT = Duration.of(5, MINUTES);

    private static final Duration AUTHORIZATION_TOKEN_REQUEST_TIME_LIMIT = Duration.of(5, MINUTES);

    private static final Duration REDIS_TIME_TO_LIVE_ADD_TIME = Duration.of(3, MINUTES);

    public static final String AUTHORIZATION_KEY_PREFIX = "authorization:";

    public static final String AUTHORIZATION_CONSENT_STATE_KEY_PREFIX = "authorization:consent:state:";

    public static final String AUTHORIZATION_CODE_KEY_PREFIX = "authorization:code:";

    public static final String AUTHORIZATION_ACCESS_TOKEN_KEY_PREFIX = "authorization:access_token:";

    public static final String AUTHORIZATION_REFRESH_TOKEN_KEY_PREFIX = "authorization:refresh_token:";

    private final ObjectMapper objectMapper = new ObjectMapper()
            .registerModules(getModules(this.getClass().getClassLoader()))
            .registerModule(new OAuth2AuthorizationServerJackson2Module())
            .addMixIn(CustomAuthorization.class, CustomAuthorizationMixIn.class)
            .addMixIn(CustomOAuth2User.class, CustomOauth2UserMixIn.class);

    private final RegisteredClientRepository registeredClientRepository;

    private final ValueOperations<String, String> valueOperations;

    private final StringRedisTemplate stringRedisTemplate;

    public RedisOauth2AuthorizationService(StringRedisTemplate stringRedisTemplate,
                                           RegisteredClientRepository registeredClientRepository) {
        this.stringRedisTemplate = stringRedisTemplate;
        this.valueOperations = stringRedisTemplate.opsForValue();
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        try {
            Assert.notNull(authorization, "authorization cannot be null");

            if (isAfterAccessTokenIssued(authorization)) {
                saveAuthorizationTokens(authorization);

                return;
            }

            if (isConsent(authorization)) {
                saveAuthorizationConsentState(authorization);

                return;
            }

            saveAuthorizationCode(authorization);
        } catch (Exception e) {
            e.printStackTrace();
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        try {
            Assert.notNull(authorization, "authorization cannot be null");

            stringRedisTemplate.delete(AUTHORIZATION_KEY_PREFIX + authorization.getId());
        } catch (Exception e) {
            e.printStackTrace();
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
    }

    @Override
    public OAuth2Authorization findById(String id) {
        try {
            Assert.hasText(id, "id cannot be empty");

            return deserialize(valueOperations.get(AUTHORIZATION_KEY_PREFIX + id));
        } catch (Exception e) {
            e.printStackTrace();
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
    }

    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        if (!hasText(token)) {
            throw new OAuth2AuthenticationException(INVALID_REQUEST);
        }

        try {
            String authorizationId = findAuthorizationIdByTokenAndTokenType(token, tokenType);

            if (authorizationId == null) {
                return null;
            }

            return deserialize(valueOperations.get(AUTHORIZATION_KEY_PREFIX + authorizationId));
        } catch (Exception e) {
            e.printStackTrace();
            throw new OAuth2AuthenticationException(SERVER_ERROR);
        }
    }

    private String findAuthorizationIdByTokenAndTokenType(String token, OAuth2TokenType tokenType) {
        if (tokenType == null) {
            // token introspect, token revocation request
            return valueOperations.get(AUTHORIZATION_ACCESS_TOKEN_KEY_PREFIX + encrypt(token));
        }

        if (STATE.equals(tokenType.getValue())) {
            // authorization request(after consent)
            return valueOperations.get(AUTHORIZATION_CONSENT_STATE_KEY_PREFIX + token);
        }

        if (CODE.equals(tokenType.getValue())) {
            // token request, token introspect, token revocation request
            return valueOperations.get(AUTHORIZATION_CODE_KEY_PREFIX + token);
        }

        if (ACCESS_TOKEN.equals(tokenType)) {
            // oidc userinfo request, oidc client registration request
            return valueOperations.get(AUTHORIZATION_ACCESS_TOKEN_KEY_PREFIX + encrypt(token));
        }

        if (REFRESH_TOKEN.equals(tokenType)) {
            // token refresh request
            return valueOperations.get(AUTHORIZATION_REFRESH_TOKEN_KEY_PREFIX + encrypt(token));
        }

        return null;
    }

    private void saveAuthorizationTokens(OAuth2Authorization authorization) {
        stringRedisTemplate.executePipelined((RedisCallback<?>) connection -> {
            RedisStringCommands redisStringCommands = connection.stringCommands();

            RegisteredClient registeredClient = findClientByRegisteredClientId(authorization.getRegisteredClientId());

            Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);

            if (authorizationCode != null) {
                String authorizationCodeValue = authorizationCode
                        .getToken()
                        .getTokenValue();

                redisStringCommands.set(
                        toBytes(AUTHORIZATION_CODE_KEY_PREFIX + authorizationCodeValue),
                        toBytes(authorization.getId()),
                        from(getClientAccessTokenTimeToLive(registeredClient)),
                        UPSERT
                );
            }

            Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();

            String accessTokenValue = accessToken
                    .getToken()
                    .getTokenValue();

            redisStringCommands.set(
                    toBytes(AUTHORIZATION_ACCESS_TOKEN_KEY_PREFIX + encrypt(accessTokenValue)),
                    toBytes(authorization.getId()),
                    from(getClientAccessTokenTimeToLive(registeredClient)),
                    UPSERT
            );

            Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();

            if (refreshToken != null) {
                String refreshTokenValue = refreshToken
                        .getToken()
                        .getTokenValue();

                redisStringCommands.set(
                        toBytes(AUTHORIZATION_REFRESH_TOKEN_KEY_PREFIX + encrypt(refreshTokenValue)),
                        toBytes(authorization.getId()),
                        from(getClientRefreshTokenTimeToLive(registeredClient)),
                        UPSERT
                );
            }

            redisStringCommands.set(
                    toBytes(AUTHORIZATION_KEY_PREFIX + authorization.getId()),
                    toBytes(serialize(authorization)),
                    from(getClientAuthorizationTimeToLive(registeredClient)),
                    UPSERT
            );

            return null;
        });
    }

    private void saveAuthorizationCode(OAuth2Authorization authorization) {
        stringRedisTemplate.executePipelined((RedisCallback<?>) connection -> {
            RedisStringCommands redisStringCommands = connection.stringCommands();

            Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);

            if (authorizationCode != null) {
                String authorizationCodeValue = authorizationCode
                        .getToken()
                        .getTokenValue();

                redisStringCommands.set(
                        toBytes(AUTHORIZATION_CODE_KEY_PREFIX + authorizationCodeValue),
                        toBytes(authorization.getId()),
                        from(AUTHORIZATION_TOKEN_REQUEST_TIME_LIMIT),
                        UPSERT
                );
            }


            redisStringCommands.set(
                    toBytes(AUTHORIZATION_KEY_PREFIX + authorization.getId()),
                    toBytes(serialize(authorization)),
                    from(AUTHORIZATION_TOKEN_REQUEST_TIME_LIMIT),
                    UPSERT
            );

            return null;
        });
    }

    private void saveAuthorizationConsentState(OAuth2Authorization authorization) {
        stringRedisTemplate.executePipelined((RedisCallback<?>) connection -> {
            RedisStringCommands redisStringCommands = connection.stringCommands();

            redisStringCommands.set(
                    toBytes(AUTHORIZATION_CONSENT_STATE_KEY_PREFIX + authorization.getAttribute(STATE)),
                    toBytes(authorization.getId()),
                    from(AUTHORIZATION_CONSENT_TIME_LIMIT),
                    UPSERT
            );

            redisStringCommands.set(
                    toBytes(AUTHORIZATION_KEY_PREFIX + authorization.getId()),
                    toBytes(serialize(authorization)),
                    from(AUTHORIZATION_CONSENT_TIME_LIMIT),
                    UPSERT
            );

            return null;
        });
    }

    private boolean isConsent(OAuth2Authorization authorization) {
        return authorization.getAttribute(STATE) != null;
    }

    private boolean isAfterAccessTokenIssued(OAuth2Authorization authorization) {
        return authorization.getAccessToken() != null;
    }

    private RegisteredClient findClientByRegisteredClientId(String registeredClientId) {
        RegisteredClient registeredClient = registeredClientRepository.findById(registeredClientId);

        if (registeredClient == null) {
            throw new DataRetrievalFailureException(
                    format(
                            "The RegisteredClient with id '%s' was not found in the RegisteredClientRepository.",
                            registeredClientId
                    )
            );
        }

        return registeredClient;
    }

    private boolean hasRefreshTokenGrant(RegisteredClient registeredClient) {
        return registeredClient
                .getAuthorizationGrantTypes()
                .contains(AuthorizationGrantType.REFRESH_TOKEN);
    }

    private boolean isPublicClient(RegisteredClient registeredClient) {
        return registeredClient.getClientSecret() == null;
    }

    private Duration getClientRefreshTokenTimeToLive(RegisteredClient registeredClient) {
        return registeredClient
                .getTokenSettings()
                .getRefreshTokenTimeToLive()
                .plus(REDIS_TIME_TO_LIVE_ADD_TIME);
    }

    private Duration getClientAccessTokenTimeToLive(RegisteredClient registeredClient) {
        return registeredClient
                .getTokenSettings()
                .getAccessTokenTimeToLive()
                .plus(REDIS_TIME_TO_LIVE_ADD_TIME);
    }

    private Duration getClientAuthorizationTimeToLive(RegisteredClient registeredClient) {
        if (isPublicClient(registeredClient) || !hasRefreshTokenGrant(registeredClient)) {
            return getClientAccessTokenTimeToLive(registeredClient);
        }

        return getClientRefreshTokenTimeToLive(registeredClient);
    }

    private OAuth2Authorization toObject(CustomAuthorization entity) {
        OAuth2Authorization.Builder builder = OAuth2Authorization
                .withRegisteredClient(findClientByRegisteredClientId(entity.getRegisteredClientId()))
                .id(entity.getId())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
                .authorizedScopes(entity.getAuthorizedScopes())
                .attributes(attributes -> attributes.putAll(entity.getAttributes()));

        if (entity.getState() != null) {
            builder.attribute(STATE, entity.getState());
        }

        if (entity.getAuthorizationCodeValue() != null) {
            OAuth2AuthorizationCode authorizationCode = new OAuth2AuthorizationCode(
                    entity.getAuthorizationCodeValue(),
                    entity.getAuthorizationCodeIssuedAt(),
                    entity.getAuthorizationCodeExpiresAt()
            );

            builder.token(authorizationCode, metadata -> metadata.putAll(entity.getAuthorizationCodeMetadata()));
        }

        if (entity.getAccessTokenValue() != null) {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt(),
                    entity.getAccessTokenScopes()
            );

            builder.token(accessToken, metadata -> metadata.putAll(entity.getAccessTokenMetadata()));
        }

        if (entity.getRefreshTokenValue() != null) {
            OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt()
            );

            builder.token(refreshToken, metadata -> metadata.putAll(entity.getRefreshTokenMetadata()));
        }

        if (entity.getOidcIdTokenValue() != null) {
            OidcIdToken idToken = new OidcIdToken(
                    entity.getOidcIdTokenValue(),
                    entity.getOidcIdTokenIssuedAt(),
                    entity.getOidcIdTokenExpiresAt(),
                    entity.getOidcIdTokenClaims()
            );

            builder.token(idToken, metadata -> metadata.putAll(entity.getOidcIdTokenMetadata()));
        }

        return builder.build();
    }

    private CustomAuthorization toEntity(OAuth2Authorization authorization) {
        CustomAuthorizationBuilder builder = CustomAuthorization
                .builder()
                .id(authorization.getId())
                .registeredClientId(authorization.getRegisteredClientId())
                .principalName(authorization.getPrincipalName())
                .authorizationGrantType(authorization.getAuthorizationGrantType().getValue())
                .authorizedScopes(authorization.getAuthorizedScopes())
                .attributes(authorization.getAttributes())
                .state(authorization.getAttribute(STATE));

        Token<OAuth2AuthorizationCode> authorizationCode = authorization.getToken(OAuth2AuthorizationCode.class);

        if (authorizationCode != null) {
            OAuth2AuthorizationCode token = authorizationCode.getToken();

            builder
                    .authorizationCodeValue(token.getTokenValue())
                    .authorizationCodeIssuedAt(token.getIssuedAt())
                    .authorizationCodeExpiresAt(token.getExpiresAt())
                    .authorizationCodeMetadata(authorizationCode.getMetadata());
        }

        Token<OAuth2AccessToken> accessToken = authorization.getAccessToken();

        if (accessToken != null) {
            OAuth2AccessToken token = accessToken.getToken();

            builder
                    .accessTokenValue(token.getTokenValue())
                    .accessTokenIssuedAt(token.getIssuedAt())
                    .accessTokenExpiresAt(token.getExpiresAt())
                    .accessTokenMetadata(accessToken.getMetadata())
                    .accessTokenScopes(token.getScopes());
        }

        Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();

        if (refreshToken != null) {
            OAuth2RefreshToken token = refreshToken.getToken();

            builder
                    .refreshTokenValue(token.getTokenValue())
                    .refreshTokenIssuedAt(token.getIssuedAt())
                    .refreshTokenExpiresAt(token.getExpiresAt())
                    .refreshTokenMetadata(refreshToken.getMetadata());
        }

        Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);

        if (oidcIdToken != null) {
            OidcIdToken token = oidcIdToken.getToken();

            builder
                    .oidcIdTokenValue(token.getTokenValue())
                    .oidcIdTokenIssuedAt(token.getIssuedAt())
                    .oidcIdTokenExpiresAt(token.getExpiresAt())
                    .oidcIdTokenMetadata(oidcIdToken.getMetadata())
                    .oidcIdTokenClaims(token.getClaims());
        }

        return builder.build();
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
        if (AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
            return AUTHORIZATION_CODE;
        }

        if (CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
            return CLIENT_CREDENTIALS;
        }

        if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }

        return new AuthorizationGrantType(authorizationGrantType);
    }

    private String serialize(OAuth2Authorization authorization) {
        try {
            return objectMapper.writeValueAsString(toEntity(authorization));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private OAuth2Authorization deserialize(String json) {
        if (json == null) {
            return null;
        }

        try {
            return toObject(objectMapper.readValue(json, CustomAuthorization.class));
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
    }

    private byte[] toBytes(String content) {
        return content.getBytes(UTF_8);
    }

    public String encrypt(String token) {
        MessageDigest messageDigest;

        try {
            messageDigest = getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }

        byte[] digest = messageDigest.digest(token.getBytes(UTF_8));

        StringBuilder stringBuilder = new StringBuilder();

        for (byte b : digest) {
            stringBuilder.append(format("%02x", b));
        }

        return stringBuilder.toString();
    }

}
