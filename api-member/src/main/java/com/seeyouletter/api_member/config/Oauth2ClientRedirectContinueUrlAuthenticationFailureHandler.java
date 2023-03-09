package com.seeyouletter.api_member.config;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.seeyouletter.api_member.auth.config.Oauth2ClientAuthorizationRequestSaveContinueUrlFilter.REDIRECT_URI_PARAMETER_NAME;
import static org.springframework.security.oauth2.core.OAuth2ErrorCodes.SERVER_ERROR;
import static org.springframework.util.StringUtils.hasText;
import static org.springframework.web.util.UriComponentsBuilder.fromHttpUrl;

public class Oauth2ClientRedirectContinueUrlAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final String DEFAULT_FAILURE_URL = "/login";

    public Oauth2ClientRedirectContinueUrlAuthenticationFailureHandler() {
        this(DEFAULT_FAILURE_URL);
    }

    public Oauth2ClientRedirectContinueUrlAuthenticationFailureHandler(String defaultFailureUrl) {
        setDefaultFailureUrl(defaultFailureUrl + "?error");
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        String continueUrl = getContinueUrl(request);

        if (hasText(continueUrl)) {
            removeContinueUrl(request);

            getRedirectStrategy()
                    .sendRedirect(request, response, buildContinueUrlWithError(continueUrl, exception));

            return;
        }

        super.onAuthenticationFailure(request, response, exception);
    }

    private String buildContinueUrlWithError(String continueUrl, AuthenticationException exception) {
        return fromHttpUrl(continueUrl)
                .queryParam("error", extractErrorCode(exception))
                .build()
                .toString();
    }

    private String extractErrorCode(AuthenticationException exception) {
        if (exception instanceof OAuth2AuthenticationException) {
            return ((OAuth2AuthenticationException) exception)
                    .getError()
                    .getErrorCode();
        }

        return SERVER_ERROR;
    }

    private String getContinueUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return null;
        }

        Object continueUrl = session.getAttribute(REDIRECT_URI_PARAMETER_NAME);

        if (continueUrl == null) {
            return null;
        }

        return (String) continueUrl;
    }

    private void removeContinueUrl(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            return;
        }

        session.removeAttribute(REDIRECT_URI_PARAMETER_NAME);
    }

}
