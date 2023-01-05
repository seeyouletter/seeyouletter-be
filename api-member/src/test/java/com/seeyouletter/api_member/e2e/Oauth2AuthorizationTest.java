package com.seeyouletter.api_member.e2e;

import com.fasterxml.jackson.core.type.TypeReference;
import com.seeyouletter.api_member.IntegrationTestContext;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MvcResult;

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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpHeaders.LOCATION;
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

    private static final RegisteredClient publicClient;

    @Autowired
    private JwtDecoder jwtDecoder;

    static {
        publicClient = createOauth2PublicClient();
    }

    static RegisteredClient createOauth2PublicClient() {
        Set<String> allowedOidcScopes = Set.of(OPENID, PROFILE, EMAIL, ADDRESS, PHONE);
        Set<String> allowedCustomScopes = Set.of("user.read", "user.write");

        return withId(randomUUID().toString())
                .clientId("test-public-client")
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

    @BeforeAll
    static void setUp(@Autowired RegisteredClientRepository registeredClientRepository) {
        registeredClientRepository.save(publicClient);
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

    @Test
    @WithMockUser
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
        MvcResult authorizationResult = mockMvc
                .perform(
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
                .andDo(print())
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

        assertThat(queryStrings.get("state"), is(equalTo(state)));
        assertThat(queryStrings.get("code"), is(not(emptyOrNullString())));
    }

    @Test
    @WithMockUser
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

        // when & then
        MvcResult authorizationResult = mockMvc
                .perform(
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
                .andDo(print())
                .andReturn();

        Map<String, String> queryStrings = parseRedirectQueryString(authorizationResult);

        assertThat(queryStrings.get("state"), is(equalTo(state)));
        assertThat(queryStrings.get("code"), is(not(emptyOrNullString())));

        MvcResult tokenResult = mockMvc
                .perform(
                        post("/oauth2/token")
                                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                                .param("client_id", clientId)
                                .param("code", queryStrings.get("code"))
                                .param("code_verifier", codeVerifier)
                                .param("grant_type", "authorization_code")
                                .param("redirect_uri", redirectUri)
                )
                .andExpect(status().isOk())
                .andDo(print())
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
                                        parameterWithName("code_verifier").description("해시 원본 값").optional(),
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

        assertThat(nonce, is(equalTo(idToken.getClaim("nonce"))));
    }

}
