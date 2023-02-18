package com.seeyouletter.api_member.e2e;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.seeyouletter.api_member.IntegrationTestContext;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MvcResult;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpHeaders.CONTENT_TYPE;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.restdocs.mockmvc.RestDocumentationRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DisplayName(value = "Oauth2 클라이언트 인증 및 인가 테스트")
class Oauth2ClientAuthorizationTest extends IntegrationTestContext {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Nested
    class NaverOauth2Client {

        private final ClientRegistration clientRegistration = clientRegistrationRepository
                .findByRegistrationId("naver");

        @Test
        void redirectAuthorizePage() throws Exception {
            // when
            String redirectedUrl = mockMvc
                    .perform(get("/oauth2/authorization/naver"))
                    .andExpect(status().is3xxRedirection())
                    .andDo(print())
                    .andReturn()
                    .getResponse()
                    .getRedirectedUrl();

            // then
            assertThat(redirectedUrl).startsWith(clientRegistration.getProviderDetails().getAuthorizationUri());
        }

        @Test
        void receiveAuthorizeCallback() throws Exception {
            // given
            stubFor(
                    WireMock.post("/naver/oauth2.0/token")
                            .willReturn(
                                    aResponse()
                                            .withStatus(OK.value())
                                            .withHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                                            .withBodyFile("naver-token-response.json")
                            )

            );

            stubFor(
                    WireMock.get("/naver/v1/nid/me")
                            .willReturn(
                                    aResponse()
                                            .withStatus(OK.value())
                                            .withHeader(CONTENT_TYPE, APPLICATION_JSON_VALUE)
                                            .withBodyFile("naver-userinfo-response.json")
                            )

            );

            MockHttpSession mockHttpSession = new MockHttpSession();

            // when & then
            MvcResult redirectNaverAuthorizePageResult = mockMvc
                    .perform(
                            get("/oauth2/authorization/naver")
                                    .session(mockHttpSession)
                    )
                    .andExpect(status().is3xxRedirection())
                    .andDo(print())
                    .andReturn();

            Map<String, String> queryStrings = parseRedirectQueryString(redirectNaverAuthorizePageResult);

            mockMvc
                    .perform(
                            get("/login/oauth2/code/naver")
                                    .session(mockHttpSession)
                                    .param("code", "code")
                                    .param("state", queryStrings.get("state"))
                    )
                    .andExpect(status().is3xxRedirection())
                    .andDo(print());
        }

    }

    @Nested
    class KaKaoOauth2Client {

        private final ClientRegistration clientRegistration = clientRegistrationRepository
                .findByRegistrationId("kakao");

        @Test
        void redirectAuthorizePage() throws Exception {
        }

        @Test
        void receiveAuthorizeCallback() throws Exception {
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

}
