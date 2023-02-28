package com.seeyouletter.api_member.integration;

import com.seeyouletter.api_member.IntegrationTestContext;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static com.seeyouletter.api_member.config.RedisOauth2AuthorizationService.*;
import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.security.MessageDigest.getInstance;
import static java.time.Instant.now;
import static java.util.Collections.singletonMap;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CODE;
import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;

@DisplayName(value = "RedisOauth2AuthorizationService 테스트")
class RedisOauth2AuthorizationServiceTest extends IntegrationTestContext {

    private static RegisteredClient publicClient;

    @Autowired
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @BeforeAll
    static void setUp(@Autowired RegisteredClientRepository registeredClientRepository) {
        publicClient = createOauth2PublicClient();
        registeredClientRepository.save(publicClient);
    }

    @BeforeEach
    void cleanUp() {
        stringRedisTemplate
                .getConnectionFactory()
                .getConnection()
                .serverCommands()
                .flushAll();
    }

    @Nested
    @DisplayName(value = "Oauth2Authorization 생성")
    class Save {

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization consent state) 생성")
        void authorizationConsentState() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithConsent();

            // when
            oAuth2AuthorizationService.save(authorization);

            // then
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_CONSENT_STATE_KEY_PREFIX + authorization.getAttribute(STATE))).isTrue();
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_KEY_PREFIX + authorization.getId())).isTrue();
        }

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization code) 생성")
        void authorizationCode() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithCode();

            // when
            oAuth2AuthorizationService.save(authorization);

            String authorizationCodeValue = authorization
                    .getToken(OAuth2AuthorizationCode.class)
                    .getToken()
                    .getTokenValue();

            // then
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_CODE_KEY_PREFIX + authorizationCodeValue)).isTrue();
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_KEY_PREFIX + authorization.getId())).isTrue();
        }

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization tokens) 생성")
        void authorizationTokens() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithTokens();

            // when
            oAuth2AuthorizationService.save(authorization);

            String authorizationCodeValue = authorization
                    .getToken(OAuth2AuthorizationCode.class)
                    .getToken()
                    .getTokenValue();

            String accessTokenValue = authorization
                    .getAccessToken()
                    .getToken()
                    .getTokenValue();

            String refreshTokenValue = authorization
                    .getRefreshToken()
                    .getToken()
                    .getTokenValue();

            // then
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_CODE_KEY_PREFIX + authorizationCodeValue)).isTrue();
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_ACCESS_TOKEN_KEY_PREFIX + encrypt(accessTokenValue))).isTrue();
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_REFRESH_TOKEN_KEY_PREFIX + encrypt(refreshTokenValue))).isTrue();
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_KEY_PREFIX + authorization.getId())).isTrue();
        }

    }

    @Test
    @DisplayName(value = "Oauth2Authorization 제거")
    void remove() {
        // given
        List<OAuth2Authorization> authorizations = List.of(
                createOauth2AuthorizationWithConsent(),
                createOauth2AuthorizationWithCode(),
                createOauth2AuthorizationWithTokens()
        );

        authorizations.forEach(oAuth2AuthorizationService::save);

        // when
        authorizations.forEach(oAuth2AuthorizationService::remove);

        // then
        for (OAuth2Authorization authorization : authorizations) {
            assertThat(stringRedisTemplate.hasKey(AUTHORIZATION_KEY_PREFIX + authorization.getId())).isFalse();
        }
    }

    @Test
    @DisplayName(value = "Oauth2Authorization id로 조회")
    void findById() {
        // given
        List<OAuth2Authorization> authorizations = List.of(
                createOauth2AuthorizationWithConsent(),
                createOauth2AuthorizationWithCode(),
                createOauth2AuthorizationWithTokens()
        );

        authorizations.forEach(oAuth2AuthorizationService::save);

        // when & then
        for (OAuth2Authorization authorization : authorizations) {
            assertThat(authorization).isNotNull();
        }
    }

    @Nested
    @DisplayName(value = "Oauth2Authorization findByToken")
    class FindByToken {

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization consent state) token으로 조회")
        void authorizationConsentState() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithConsent();

            oAuth2AuthorizationService.save(authorization);

            // when
            OAuth2Authorization byToken = oAuth2AuthorizationService.findByToken(authorization.getAttribute(STATE), new OAuth2TokenType(STATE));

            // then
            assertThat(byToken).isNotNull();
        }

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization code) token으로 조회")
        void authorizationCode() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithCode();

            oAuth2AuthorizationService.save(authorization);

            String authorizationCodeValue = authorization
                    .getToken(OAuth2AuthorizationCode.class)
                    .getToken()
                    .getTokenValue();

            // when
            OAuth2Authorization byToken = oAuth2AuthorizationService.findByToken(authorizationCodeValue, new OAuth2TokenType(CODE));

            // then
            assertThat(byToken).isNotNull();
        }

        @Test
        @DisplayName(value = "Oauth2Authorization(authorization tokens) token으로 조회")
        void authorizationTokens() {
            // given
            OAuth2Authorization authorization = createOauth2AuthorizationWithTokens();

            oAuth2AuthorizationService.save(authorization);

            String accessTokenValue = authorization
                    .getAccessToken()
                    .getToken()
                    .getTokenValue();

            String refreshTokenValue = authorization
                    .getRefreshToken()
                    .getToken()
                    .getTokenValue();

            // when
            List<OAuth2Authorization> byTokens = Arrays.asList(
                    oAuth2AuthorizationService.findByToken(accessTokenValue, ACCESS_TOKEN),
                    oAuth2AuthorizationService.findByToken(accessTokenValue, null),
                    oAuth2AuthorizationService.findByToken(refreshTokenValue, REFRESH_TOKEN)
            );

            // then
            for (OAuth2Authorization byToken : byTokens) {
                assertThat(byToken).isNotNull();
            }
        }

    }

    static RegisteredClient createOauth2PublicClient() {
        Set<String> allowedOidcScopes = Set.of(OPENID, PROFILE, EMAIL, ADDRESS, PHONE);
        Set<String> allowedCustomScopes = Set.of("user.read", "user.write");

        return withId(randomUUID().toString())
                .clientId(randomUUID().toString())
                .clientAuthenticationMethod(NONE)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:8600/authorized")
                .scopes(scopes -> {
                    scopes.addAll(allowedOidcScopes);
                    scopes.addAll(allowedCustomScopes);
                })
                .clientSettings(
                        ClientSettings
                                .builder()
                                .requireProofKey(true)
                                .requireAuthorizationConsent(false)
                                .build()
                )
                .build();
    }

    private OAuth2Authorization createOauth2AuthorizationWithConsent() {
        return OAuth2Authorization
                .withRegisteredClient(publicClient)
                .principalName("user")
                .authorizationGrantType(AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), createPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(), createOauth2AuthorizationRequest())
                .attribute(STATE, "l__jFmG5oa5NGiandoVKcVdnYfcX501PpAud1SYF700=")
                .build();
    }

    private OAuth2Authorization createOauth2AuthorizationWithCode() {
        return OAuth2Authorization
                .withRegisteredClient(publicClient)
                .principalName("user")
                .authorizationGrantType(AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), createPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(), createOauth2AuthorizationRequest())
                .authorizedScopes(Set.of("user.read"))
                .token(createOauth2AuthorizationCode())
                .build();
    }

    private OAuth2Authorization createOauth2AuthorizationWithTokens() {
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                BEARER,
                "access-token",
                now(),
                now().plusSeconds(300),
                Set.of("user.read")
        );

        OAuth2RefreshToken refreshToken = new OAuth2RefreshToken(
                "refresh-token",
                now(),
                now().plusSeconds(300)
        );

        OidcIdToken oidcIdToken = new OidcIdToken(
                "oidc-token",
                now(),
                now().plusSeconds(300),
                singletonMap("sub", "user")
        );

        return OAuth2Authorization
                .withRegisteredClient(publicClient)
                .principalName("user")
                .authorizationGrantType(AUTHORIZATION_CODE)
                .attribute(Principal.class.getName(), createPrincipal())
                .attribute(OAuth2AuthorizationRequest.class.getName(), createOauth2AuthorizationRequest())
                .authorizedScopes(Set.of("user.read"))
                .token(createOauth2AuthorizationCode())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .token(oidcIdToken)
                .build();
    }

    private OAuth2AuthorizationCode createOauth2AuthorizationCode() {
        return new OAuth2AuthorizationCode(
                randomUUID().toString(),
                now(),
                now().plusSeconds(300)
        );
    }

    private OAuth2AuthorizationRequest createOauth2AuthorizationRequest() {
        return OAuth2AuthorizationRequest
                .authorizationCode()
                .authorizationUri("http://localhost:8600/oauth2/authorize")
                .clientId("seeyouletter")
                .redirectUri("http://127.0.0.1:8600/authorized")
                .scopes(Set.of("user.read"))
                .state("123")
                .additionalParameters(
                        Map.of(
                                "code_challenge_method", "S256",
                                "nonce", "abc",
                                "code_challenge", "yoxj8-ou9k5pqKXo-yHfhcqcoGYGAiP_bbzerJP1HIg"
                        )
                )
                .build();
    }

    private UsernamePasswordAuthenticationToken createPrincipal() {
        return new UsernamePasswordAuthenticationToken(
                "user",
                "password",
                AuthorityUtils.createAuthorityList("ROLE_user.read")
        );
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
