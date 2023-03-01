package com.seeyouletter.api_member.e2e;

import com.fasterxml.jackson.core.type.TypeReference;
import com.seeyouletter.api_member.IntegrationTestContext;
import com.seeyouletter.api_member.config.WithMockOauth2User;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.*;
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
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static java.lang.String.join;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.security.MessageDigest.getInstance;
import static java.util.UUID.randomUUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.*;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.restdocs.headers.HeaderDocumentation.*;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.post;
import static org.springframework.restdocs.payload.PayloadDocumentation.fieldWithPath;
import static org.springframework.restdocs.payload.PayloadDocumentation.responseFields;
import static org.springframework.restdocs.request.RequestDocumentation.parameterWithName;
import static org.springframework.restdocs.request.RequestDocumentation.requestParameters;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName(value = "Oauth2 인증 및 인가 테스트")
class Oauth2AuthorizationTest extends IntegrationTestContext {

    private static RegisteredClient publicClient;

    @Autowired
    private JwtDecoder jwtDecoder;

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
                .flushAll();
    }

    @Nested
    @WithMockUser
    @DisplayName(value = "first party 유저 세션의 Oauth2 인증 및 인가")
    class FirstPartyUserSessionOauth2Authorization {

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
            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andDo(
                            document(
                                    "authorization",
                                    REQUEST_PREPROCESSOR,
                                    RESPONSE_PREPROCESSOR,
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            // when & then
            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andDo(
                            document(
                                    "token",
                                    REQUEST_PREPROCESSOR,
                                    RESPONSE_PREPROCESSOR,
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            post("/oauth2/introspect")
                                    .contentType(APPLICATION_FORM_URLENCODED)
                                    .param("client_id", clientId)
                                    .param("code", code)
                                    .param("code_verifier", codeVerifier)
                                    .param("grant_type", "authorization_code")
                                    .param("redirect_uri", redirectUri)
                                    .param("token", accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print())
                    .andDo(
                            document(
                                    "introspect",
                                    REQUEST_PREPROCESSOR,
                                    RESPONSE_PREPROCESSOR,
                                    requestHeaders(
                                            headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                    ),
                                    requestParameters(
                                            parameterWithName("client_id").description("클라이언트 id"),
                                            parameterWithName("code").description("인가 코드"),
                                            parameterWithName("code_verifier").description("해시 원본 값"),
                                            parameterWithName("grant_type").description("인증 방식, authorization_code 고정으로 사용"),
                                            parameterWithName("redirect_uri").description("리다이렉트 callback uri"),
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            post("/oauth2/revoke")
                                    .contentType(APPLICATION_FORM_URLENCODED)
                                    .param("client_id", clientId)
                                    .param("code", code)
                                    .param("code_verifier", codeVerifier)
                                    .param("grant_type", "authorization_code")
                                    .param("redirect_uri", redirectUri)
                                    .param("token", accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print())
                    .andDo(
                            document(
                                    "revoke",
                                    REQUEST_PREPROCESSOR,
                                    RESPONSE_PREPROCESSOR,
                                    requestHeaders(
                                            headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                    ),
                                    requestParameters(
                                            parameterWithName("client_id").description("클라이언트 id"),
                                            parameterWithName("code").description("인가 코드"),
                                            parameterWithName("code_verifier").description("해시 원본 값"),
                                            parameterWithName("grant_type").description("인증 방식, authorization_code 고정으로 사용"),
                                            parameterWithName("redirect_uri").description("리다이렉트 callback uri"),
                                            parameterWithName("token").description("엑세스 토큰")
                                    )
                            )
                    );
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            get("/userinfo")
                                    .header(AUTHORIZATION, "Bearer " + accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print())
                    .andDo(
                            document(
                                    "userinfo",
                                    REQUEST_PREPROCESSOR,
                                    RESPONSE_PREPROCESSOR,
                                    requestHeaders(
                                            headerWithName(AUTHORIZATION).description("Bearer {access_token}")
                                    ),
                                    responseHeaders(
                                            headerWithName(CONTENT_TYPE).description(CONTENT_TYPE)
                                    ),
                                    responseFields(
                                            fieldWithPath("sub").description("인가 요청자")
                                    )
                            )
                    );
        }

    }

    @Nested
    @WithMockOauth2User
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
            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            // when & then
            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            post("/oauth2/introspect")
                                    .contentType(APPLICATION_FORM_URLENCODED)
                                    .param("client_id", clientId)
                                    .param("code", code)
                                    .param("code_verifier", codeVerifier)
                                    .param("grant_type", "authorization_code")
                                    .param("redirect_uri", redirectUri)
                                    .param("token", accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print());
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            post("/oauth2/revoke")
                                    .contentType(APPLICATION_FORM_URLENCODED)
                                    .param("client_id", clientId)
                                    .param("code", code)
                                    .param("code_verifier", codeVerifier)
                                    .param("grant_type", "authorization_code")
                                    .param("redirect_uri", redirectUri)
                                    .param("token", accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print());
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

            MvcResult authorizationResult = performAuthorizationRequest(clientId, redirectUri, scope, codeChallenge, state, nonce)
                    .andReturn();

            String code = parseRedirectQueryString(authorizationResult)
                    .get("code");

            MvcResult tokenResult = performTokenRequest(clientId, redirectUri, codeVerifier, code)
                    .andReturn();

            String accessTokenValue = jwtDecoder
                    .decode((String) parsePayloadFields(tokenResult).get("access_token"))
                    .getTokenValue();

            // when & then
            mockMvc
                    .perform(
                            get("/userinfo")
                                    .header(AUTHORIZATION, "Bearer " + accessTokenValue)
                    )
                    .andExpect(status().isOk())
                    .andDo(print());
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

    private ResultActions performAuthorizationRequest(String clientId,
                                                      String redirectUri,
                                                      String scope,
                                                      String codeChallenge,
                                                      String state,
                                                      String nonce) throws Exception {
        return mockMvc.perform(
                get("/oauth2/authorize")
                        .with(csrf())
                        .queryParam("client_id", clientId)
                        .queryParam("redirect_uri", redirectUri)
                        .queryParam("scope", scope)
                        .queryParam("response_type", "code")
                        .queryParam("code_challenge", codeChallenge)
                        .queryParam("code_challenge_method", "S256")
                        .queryParam("state", state)
                        .queryParam("nonce", nonce)
        )
                .andExpect(status().is3xxRedirection())
                .andDo(print());
    }

    private ResultActions performTokenRequest(String clientId,
                                              String redirectUri,
                                              String codeVerifier,
                                              String code) throws Exception {
        return mockMvc
                .perform(
                        post("/oauth2/token")
                                .contentType(APPLICATION_FORM_URLENCODED)
                                .param("client_id", clientId)
                                .param("code", code)
                                .param("code_verifier", codeVerifier)
                                .param("grant_type", "authorization_code")
                                .param("redirect_uri", redirectUri)
                )
                .andExpect(status().isOk())
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
