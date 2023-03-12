package com.seeyouletter.api_member.config;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.seeyouletter.api_member.auth.config.Oauth2ClientAuthorizationRequestSaveContinueUrlFilter.REDIRECT_URI_PARAMETER_NAME;
import static org.springframework.util.StringUtils.hasText;

public class Oauth2ClientRedirectContinueUrlAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String continueUrl = getContinueUrl(request);

        if (hasText(continueUrl)) {
            removeContinueUrl(request);

            clearAuthenticationAttributes(request);

            getRedirectStrategy()
                    .sendRedirect(request, response, continueUrl);

            return;
        }

        super.onAuthenticationSuccess(request, response, authentication);
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
