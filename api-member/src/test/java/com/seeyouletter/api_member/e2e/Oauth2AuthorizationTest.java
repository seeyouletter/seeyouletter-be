package com.seeyouletter.api_member.e2e;

import com.fasterxml.jackson.core.type.TypeReference;
import com.seeyouletter.api_member.IntegrationTestContext;
import com.seeyouletter.api_member.config.WithMockOauth2User;
import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.repository.UserRepository;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod.S256;
import static com.seeyouletter.api_member.config.RestDocsConfiguration.defaultDocument;
import static com.seeyouletter.domain_member.enums.GenderType.MALE;
import static java.lang.String.join;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.security.MessageDigest.getInstance;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.MediaType.*;
import static org.springframework.restdocs.headers.HeaderDocumentation.*;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.*;
import static org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType.CODE;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DisplayName(value = "Oauth2 인증 및 인가 테스트")
class Oauth2AuthorizationTest extends IntegrationTestContext {

    private static final RegisteredClient publicClient = createOauth2PublicClient();

    private static final String testUsername = "test@seeyouletter.kr";

    @Autowired
    private JwtDecoder jwtDecoder;

    @Autowired
    private StringRedisTemplate stringRedisTemplate;

    @BeforeAll
    static void beforeAll(@Autowired RegisteredClientRepository registeredClientRepository,
                          @Autowired UserRepository userRepository) {
        registeredClientRepository.save(publicClient);
        userRepository.save(createUser());
    }

    @AfterAll
    static void afterAll(@Autowired UserRepository userRepository) {
        userRepository.deleteAll();
    }

    @BeforeEach
    void beforeEach() {
        stringRedisTemplate
                .getConnectionFactory()
                .getConnection()
                .flushAll();
    }

    @Nested
    @WithMockUser(username = testUsername)
    @DisplayName(value = "first party 유저 세션의 Oauth2 인증 및 인가")
    class FirstPartyUserSessionOauth2Authorization {

        @Nested
        @DisplayName(value = "authorization")
        class Authorization {

            @Test
            @DisplayName(value = "authorization")
            void authorization() throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andDo(
                                defaultDocument(
                                        requestParameters(
                                                parameterWithName("client_id").description("클라이언트 id"),
                                                parameterWithName("redirect_uri").description("리다이렉트 callback uri"),
                                                parameterWithName("scope").description("토큰의 인가 범위").optional(),
                                                parameterWithName("response_type").description("응답 유형, code 고정으로 사용"),
                                                parameterWithName("code_challenge").description("해시 값, Base64(SHA256(code_verifier))"),
                                                parameterWithName("code_challenge_method").description("해시 방식, S256 고정으로 사용"),
                                                parameterWithName("state").description("리다이렉트 callback uri로 전달되는 값").optional(),
                                                parameterWithName("nonce").description("id_token claim에 포함되는 값").optional()
                                        ),
                                        responseHeaders(
                                                headerWithName(LOCATION).description(LOCATION)
                                        )
                                )
                        )
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                Map<String, String> queryStrings = parseRedirectQueryString(authorizationResult);

                assertThat(queryStrings.get("state")).isEqualTo(state);
                assertThat(queryStrings.get("code")).isNotEmpty();
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_client_id", ""})
            @DisplayName(value = "authorization 유효하지 않은 client_id")
            void failAuthorizationWhenInvalidOrEmptyClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andReturn();
            }

            @ParameterizedTest
            @ValueSource(strings = {"https://invalid.redirect.uri", ""})
            @DisplayName(value = "authorization 유효하지 않은 redirect_uri")
            void failAuthorizationWhenInvalidOrEmptyRedirectUri(String redirectUri) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andReturn();
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_response_type", ""})
            @DisplayName(value = "authorization 유효하지 않은 response_type")
            void failAuthorizationWhenInvalidOrEmptyResponseType(String responseType) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                performAuthorizationRequest(clientId, redirectUri, scope, responseType, codeChallenge, S256.getValue(), state, nonce)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andReturn();
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_scope", "invalid_scope invalid_scope2"})
            @DisplayName(value = "authorization 유효하지 않은 scope")
            void failAuthorizationWhenInvalidScope(String scope) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andDo(defaultDocument())
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                Map<String, String> queryStrings = parseRedirectQueryString(authorizationResult);

                assertThat(queryStrings.get("error")).isEqualTo(INVALID_SCOPE);
                assertThat(queryStrings.get("error_description")).isNotEmpty();
                assertThat(queryStrings.get("error_uri")).isNotEmpty();
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_code_challenge_method", ""})
            @DisplayName(value = "authorization 유효하지 않은 code_challenge_method")
            void failAuthorizationWhenInvalidOrEmptyCodeChallengeMethod(String codeChallengeMethod) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                // when & then
                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, codeChallengeMethod, state, nonce)
                        .andDo(defaultDocument())
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                Map<String, String> queryStrings = parseRedirectQueryString(authorizationResult);

                assertThat(queryStrings.get("error")).isEqualTo(INVALID_REQUEST);
                assertThat(queryStrings.get("error_description")).isNotEmpty();
                assertThat(queryStrings.get("error_uri")).isNotEmpty();
            }

        }

        @Nested
        @DisplayName(value = "token")
        class Token {

            @Test
            @DisplayName(value = "token")
            void token() throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andDo(
                                defaultDocument(
                                        requestHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        requestParameters(
                                                parameterWithName("client_id").description("클라이언트 id"),
                                                parameterWithName("code").description("인가 코드"),
                                                parameterWithName("code_verifier").description("해시 원본 값"),
                                                parameterWithName("grant_type").description("인증 방식, authorization_code 고정으로 사용"),
                                                parameterWithName("redirect_uri").description("리다이렉트 callback uri")
                                        ),
                                        responseHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        responseFields(
                                                fieldWithPath("access_token").description("엑세스 토큰"),
                                                fieldWithPath("scope").description("엑세스 토큰의 인가 범위"),
                                                fieldWithPath("id_token").description("인증 토큰, 인가 요청시 scope로 openid를 전달한 경우에만 발급").optional(),
                                                fieldWithPath("token_type").description("토큰 타입, Bearer 고정으로 사용"),
                                                fieldWithPath("expires_in").description("토큰의 남은 유효기간")
                                        )
                                )
                        )
                        .andExpect(status().isOk())
                        .andReturn();

                Map<String, Object> fields = parsePayloadFields(tokenResult);
                Jwt idToken = jwtDecoder.decode((String) fields.get("id_token"));

                assertThat(nonce).isEqualTo(idToken.getClaim("nonce"));
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "token 입력되지 않은 client_id")
            void failTokenWhenEmptyClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_client_id"})
            @DisplayName(value = "token 유효하지 않은 client_id")
            void failTokenWhenInvalidClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andDo(defaultDocument())
                        .andExpect(status().isUnauthorized())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_CLIENT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"https://invalid.redirect.uri", ""})
            @DisplayName(value = "token 유효하지 않은 redirect_uri")
            void failTokenWhenInvalidOrEmptyRedirectUri(String redirectUri) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, publicClient.getRedirectUris().stream().findFirst().orElseThrow(), scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_GRANT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_code_verifier", ""})
            @DisplayName(value = "token 유효하지 않은 code_verifier")
            void failTokenWhenInvalidOrEmptyCodeVerifier(String codeVerifier) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeChallenge = generateCodeChallenge(generateCodeVerifier());
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_GRANT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_grant_type", "implicit", "password", ""})
            @DisplayName(value = "token 유효하지 않은 grant_type")
            void failTokenWhenInvalidOrEmptyGrantType(String grantType) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, grantType, code)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(UNSUPPORTED_GRANT_TYPE))
                        .andExpect(jsonPath("$.error_description").exists())
                        .andExpect(jsonPath("$.error_uri").exists());
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "token 입력되지 않은 authorization_code")
            void failTokenWhenEmptyAuthorizationCode(String authorizationCode) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), authorizationCode)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_authorization_code"})
            @DisplayName(value = "token 유효하지 않은 authorization_code")
            void failTokenWhenInvalidAuthorizationCode(String authorizationCode) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                // when & then
                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), authorizationCode)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_GRANT));
            }

        }

        @Nested
        @DisplayName(value = "introspect")
        class Introspect {

            @Test
            @DisplayName(value = "introspect")
            void introspect() throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andExpect(status().isOk())
                        .andDo(
                                defaultDocument(
                                        requestHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        requestParameters(
                                                parameterWithName("client_id").description("클라이언트 id"),
                                                parameterWithName("code").description("인가 코드"),
                                                parameterWithName("code_verifier").description("해시 원본 값"),
                                                parameterWithName("grant_type").description("인증 방식, authorization_code 고정으로 사용"),
                                                parameterWithName("token").description("엑세스 토큰")
                                        ),
                                        responseHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        responseFields(
                                                fieldWithPath("active").description("엑세스 토큰의 유효 여부"),
                                                fieldWithPath("sub").description("인가 요청자"),
                                                fieldWithPath("aud").description("인가 클라이언트"),
                                                fieldWithPath("nbf").description("엑세스 토큰이 활성화된 시간(unix time)"),
                                                fieldWithPath("scope").description("엑세스 토큰의 인가 범위"),
                                                fieldWithPath("iss").description("엑세스 토큰 발행자"),
                                                fieldWithPath("exp").description("엑세스 토큰이 만료되는 시간(unix time)"),
                                                fieldWithPath("iat").description("엑세스 토큰이 발행된 시간(unix time)"),
                                                fieldWithPath("client_id").description("클라이언트 id"),
                                                fieldWithPath("token_type").description("토큰 타입, Bearer 고정으로 사용")
                                        )
                                )
                        );
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "introspect 입력되지 않은 client_id")
            void failIntrospectWhenEmptyClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(publicClient.getClientId(), redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_client_id"})
            @DisplayName(value = "introspect 유효하지 않은 client_id")
            void failIntrospectWhenInvalidClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(publicClient.getClientId(), redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isUnauthorized())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_CLIENT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_code_verifier", ""})
            @DisplayName(value = "introspect 유효하지 않은 code_verifier")
            void failIntrospectWhenInvalidOrEmptyCodeVerifier(String codeVerifier) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String validCodeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(validCodeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, validCodeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_GRANT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_grant_type", "implicit", "password", ""})
            @DisplayName(value = "introspect 유효하지 않은 grant_type")
            void failIntrospectWhenInvalidOrEmptyGrantType(String grantType) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, grantType, code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_CLIENT));
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "introspect 입력되지 않은 access_token")
            void failIntrospectWhenEmptyAccessToken(String accessToken) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessToken)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST))
                        .andExpect(jsonPath("$.error_description").exists())
                        .andExpect(jsonPath("$.error_uri").exists());
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_access_token"})
            @DisplayName(value = "introspect 유효하지 않은 access_token")
            void failIntrospectWhenInvalidAccessToken(String accessToken) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                // when & then
                performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessToken)
                        .andDo(defaultDocument())
                        .andExpect(status().isOk())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_VALUE))
                        .andExpect(jsonPath("$.active").value(false));
            }

        }

        @Nested
        @DisplayName(value = "revoke")
        class Revoke {

            @Test
            @DisplayName(value = "revoke")
            void revoke() throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andExpect(status().isOk())
                        .andDo(
                                defaultDocument(
                                        requestHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        requestParameters(
                                                parameterWithName("client_id").description("클라이언트 id"),
                                                parameterWithName("code").description("인가 코드"),
                                                parameterWithName("code_verifier").description("해시 원본 값"),
                                                parameterWithName("grant_type").description("인증 방식, authorization_code 고정으로 사용"),
                                                parameterWithName("token").description("엑세스 토큰")
                                        )
                                )
                        );
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "revoke 입력되지 않은 client_id")
            void failRevokeWhenEmptyClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(publicClient.getClientId(), redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_client_id"})
            @DisplayName(value = "revoke 유효하지 않은 client_id")
            void failRevokeWhenInvalidClientId(String clientId) throws Exception {
                // given
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(publicClient.getClientId(), redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(publicClient.getClientId(), redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isUnauthorized())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_CLIENT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_code_verifier", ""})
            @DisplayName(value = "revoke 유효하지 않은 code_verifier")
            void failRevokeWhenInvalidOrEmptyCodeVerifier(String codeVerifier) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String validCodeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(validCodeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, validCodeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_GRANT));
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_grant_type", "implicit", "password", ""})
            @DisplayName(value = "revoke 유효하지 않은 grant_type")
            void failRevokeWhenInvalidOrEmptyGrantType(String grantType) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performRevokeRequest(clientId, codeVerifier, grantType, code, accessTokenValue)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_CLIENT));
            }

            @ParameterizedTest
            @NullAndEmptySource
            @DisplayName(value = "revoke 입력되지 않은 access_token")
            void failRevokeWhenEmptyAccessToken(String accessToken) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessToken)
                        .andDo(defaultDocument())
                        .andExpect(status().isBadRequest())
                        .andExpect(header().string(CONTENT_TYPE, APPLICATION_JSON_UTF8_VALUE))
                        .andExpect(jsonPath("$.error").value(INVALID_REQUEST))
                        .andExpect(jsonPath("$.error_description").exists())
                        .andExpect(jsonPath("$.error_uri").exists());
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_access_token"})
            @DisplayName(value = "revoke 유효하지 않은 access_token")
            void failRevokeWhenInvalidAccessToken(String accessToken) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                // when & then
                performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessToken)
                        .andDo(defaultDocument())
                        .andExpect(status().isOk());
            }

        }

        @Nested
        @DisplayName(value = "userinfo")
        class Userinfo {

            @Test
            @DisplayName(value = "userinfo")
            void userinfo() throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                String accessTokenValue = jwtDecoder
                        .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                        .getTokenValue();

                // when & then
                performUserinfoRequest(accessTokenValue)
                        .andExpect(status().isOk())
                        .andDo(
                                defaultDocument(
                                        requestHeaders(
                                                headerWithName(AUTHORIZATION).description("Bearer {access_token}")
                                        ),
                                        responseHeaders(
                                                headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                        ),
                                        responseFields(
                                                fieldWithPath("sub").description("인가 요청자"),
                                                fieldWithPath("preferred_username").description("사용되는 이름"),
                                                fieldWithPath("name").description("이름"),
                                                fieldWithPath("nickname").description("닉네임"),
                                                fieldWithPath("profile").description("프로필"),
                                                fieldWithPath("birthdate").description("생년월일").optional(),
                                                fieldWithPath("gender").description("성별"),
                                                fieldWithPath("email").description("이메일"),
                                                fieldWithPath("email_verified").description("이메일 검증 여부"),
                                                fieldWithPath("phone_number").description("휴대전화번호").optional(),
                                                fieldWithPath("phone_number_verified").description("휴대전화번호 검증 여부")
                                        )
                                )
                        );
            }

            @ParameterizedTest
            @ValueSource(strings = {"invalid_access_token", ""})
            @DisplayName(value = "userinfo")
            void failUserinfoWhenInvalidOrEmptyAccessToken(String accessToken) throws Exception {
                // given
                String clientId = publicClient.getClientId();
                String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
                String scope = join(" ", publicClient.getScopes());
                String codeVerifier = generateCodeVerifier();
                String codeChallenge = generateCodeChallenge(codeVerifier);
                String state = randomUUID().toString();
                String nonce = randomUUID().toString();

                MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                        .andExpect(status().is3xxRedirection())
                        .andReturn();

                String code = parseRedirectQueryString(authorizationResult)
                        .get("code");

                performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                        .andExpect(status().isOk())
                        .andReturn();

                // when & then
                performUserinfoRequest(accessToken)
                        .andDo(defaultDocument())
                        .andExpect(status().isUnauthorized());
            }

        }

    }

    @Nested
    @WithMockOauth2User(username = testUsername)
    @DisplayName(value = "third party 유저 세션의 Oauth2 인증 및 인가")
    class ThirdPartyUserSessionOauth2Authorization {

        @Test
        @DisplayName(value = "authorization")
        void authorization() throws Exception {
            // given
            String clientId = publicClient.getClientId();
            String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
            String scope = join(" ", publicClient.getScopes());
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = randomUUID().toString();
            String nonce = randomUUID().toString();

            // when & then
            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            Map<String, String> queryStrings = parseRedirectQueryString(authorizationResult);

            assertThat(queryStrings.get("state")).isEqualTo(state);
            assertThat(queryStrings.get("code")).isNotEmpty();
        }

        @Test
        @DisplayName(value = "token")
        void token() throws Exception {
            // given
            String clientId = publicClient.getClientId();
            String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
            String scope = join(" ", publicClient.getScopes());
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = randomUUID().toString();
            String nonce = randomUUID().toString();

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            // when & then
            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                    .andExpect(status().isOk())
                    .andReturn();

            Map<String, Object> fields = parsePayloadFields(tokenResult);
            Jwt idToken = jwtDecoder.decode((String) fields.get("id_token"));

            assertThat(nonce).isEqualTo(idToken.getClaim("nonce"));
        }

        @Test
        @DisplayName(value = "introspect")
        void introspect() throws Exception {
            // given
            String clientId = publicClient.getClientId();
            String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
            String scope = join(" ", publicClient.getScopes());
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = randomUUID().toString();
            String nonce = randomUUID().toString();

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                    .andExpect(status().isOk())
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            performIntrospectRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName(value = "revoke")
        void revoke() throws Exception {
            // given
            String clientId = publicClient.getClientId();
            String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
            String scope = join(" ", publicClient.getScopes());
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = randomUUID().toString();
            String nonce = randomUUID().toString();

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                    .andExpect(status().isOk())
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            performRevokeRequest(clientId, codeVerifier, AUTHORIZATION_CODE.getValue(), code, accessTokenValue)
                    .andExpect(status().isOk());
        }

        @Test
        @DisplayName(value = "userinfo")
        void userinfo() throws Exception {
            // given
            String clientId = publicClient.getClientId();
            String redirectUri = publicClient.getRedirectUris().stream().findFirst().orElseThrow();
            String scope = join(" ", publicClient.getScopes());
            String codeVerifier = generateCodeVerifier();
            String codeChallenge = generateCodeChallenge(codeVerifier);
            String state = randomUUID().toString();
            String nonce = randomUUID().toString();

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, CODE.getValue(), codeChallenge, S256.getValue(), state, nonce)
                    .andExpect(status().is3xxRedirection())
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, AUTHORIZATION_CODE.getValue(), code)
                    .andExpect(status().isOk())
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            performUserinfoRequest(accessTokenValue)
                    .andExpect(status().isOk());
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

    static User createUser() {
        return User
                .builder()
                .email(testUsername)
                .password("{noop}test1234")
                .name("테스트")
                .birth(LocalDate.now())
                .genderType(MALE)
                .howJoin("테스트를 위한 계정입니다.")
                .phone("01031157613")
                .build();
    }

    private ResultActions performAuthorizationRequest(String clientId, String redirectUri, String scope,
                                                      String responseType, String codeChallenge, String codeChallengeMethod,
                                                      String state, String nonce) throws Exception {
        return mockMvc
                .perform(
                        get("/oauth2/authorize")
                                .with(csrf())
                                .queryParam("client_id", clientId)
                                .queryParam("redirect_uri", redirectUri)
                                .queryParam("scope", scope)
                                .queryParam("response_type", responseType)
                                .queryParam("code_challenge", codeChallenge)
                                .queryParam("code_challenge_method", codeChallengeMethod)
                                .queryParam("state", state)
                                .queryParam("nonce", nonce)
                )
                .andDo(print());
    }

    private ResultActions performTokenRequest(String clientId, String redirectUri, String codeVerifier,
                                              String grantType, String code) throws Exception {
        return mockMvc
                .perform(
                        post("/oauth2/token")
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .param("client_id", clientId)
                                .param("code", code)
                                .param("code_verifier", codeVerifier)
                                .param("grant_type", grantType)
                                .param("redirect_uri", redirectUri)
                )
                .andDo(print());
    }

    private ResultActions performIntrospectRequest(String clientId, String codeVerifier, String grantType, String code,
                                                   String accessToken) throws Exception {
        return mockMvc
                .perform(
                        post("/oauth2/introspect")
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .param("client_id", clientId)
                                .param("code", code)
                                .param("code_verifier", codeVerifier)
                                .param("grant_type", grantType)
                                .param("token", accessToken)
                )
                .andDo(print());
    }

    private ResultActions performRevokeRequest(String clientId, String codeVerifier, String grantType, String code,
                                               String accessToken) throws Exception {
        return mockMvc
                .perform(
                        post("/oauth2/revoke")
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .param("client_id", clientId)
                                .param("code", code)
                                .param("code_verifier", codeVerifier)
                                .param("grant_type", grantType)
                                .param("token", accessToken)
                )
                .andDo(print());
    }

    private ResultActions performUserinfoRequest(String accessToken) throws Exception {
        return mockMvc
                .perform(
                        get("/userinfo")
                                .header(AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print());
    }

    private String generateCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];

        secureRandom.nextBytes(codeVerifier);

        return Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(codeVerifier);
    }

    private String generateCodeChallenge(String codeVerifier) {
        try {
            MessageDigest messageDigest = getInstance("SHA-256");
            byte[] bytes = codeVerifier.getBytes(US_ASCII);
            byte[] digest = messageDigest.digest(bytes);

            return Base64
                    .getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private Map<String, String> parseRedirectQueryString(MvcResult mvcResult) throws URISyntaxException {
        String redirectedUrl = mvcResult
                .getResponse()
                .getRedirectedUrl();

        return URLEncodedUtils
                .parse(new URI(redirectedUrl), UTF_8)
                .stream()
                .collect(
                        Collectors.toMap(
                                NameValuePair::getName,
                                NameValuePair::getValue
                        )
                );
    }

    private Map<String, Object> parsePayloadFields(MvcResult mvcResult) throws IOException {
        String payload = mvcResult
                .getResponse()
                .getContentAsString();

        return objectMapper.readValue(payload, new TypeReference<>() {
        });
    }

}
