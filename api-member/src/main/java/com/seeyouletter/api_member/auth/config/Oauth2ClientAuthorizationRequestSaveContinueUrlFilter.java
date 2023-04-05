package com.seeyouletter.api_member.auth.config;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Objects;

import static java.util.Collections.emptyList;
import static java.util.stream.Collectors.toUnmodifiableList;
import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
import static org.springframework.util.StringUtils.hasText;

public class Oauth2ClientAuthorizationRequestSaveContinueUrlFilter extends OncePerRequestFilter {

    private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

    public static final String REDIRECT_URI_PARAMETER_NAME = "continue";

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final AntPathRequestMatcher authorizationRequestMatcher;

    private final List<String> allowOrigins;

    public Oauth2ClientAuthorizationRequestSaveContinueUrlFilter(ClientRegistrationRepository clientRegistrationRepository) {
        this(clientRegistrationRepository, emptyList(), DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    public Oauth2ClientAuthorizationRequestSaveContinueUrlFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                                 List<String> allowOrigins) {
        this(clientRegistrationRepository, allowOrigins, DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);
    }

    public Oauth2ClientAuthorizationRequestSaveContinueUrlFilter(ClientRegistrationRepository clientRegistrationRepository,
                                                                 List<String> allowOrigins,
                                                                 String authorizationRequestBaseUri) {
        Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
        Assert.notNull(allowOrigins, "allowOrigins cannot be null");
        Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");

        this.clientRegistrationRepository = clientRegistrationRepository;
        this.authorizationRequestMatcher = new AntPathRequestMatcher(authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
        this.allowOrigins = allowOrigins
                .stream()
                .filter(Objects::nonNull)
                .map(this::trimTrailingSlash)
                .collect(toUnmodifiableList());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (matchAuthorizationRequest(request)) {
            saveContinueUrl(request);
        }

        filterChain.doFilter(request, response);
    }

    private boolean matchAuthorizationRequest(HttpServletRequest request) {
        if (!authorizationRequestMatcher.matches(request)) {
            return false;
        }

        String registrationId = authorizationRequestMatcher
                .matcher(request)
                .getVariables()
                .get(REGISTRATION_ID_URI_VARIABLE_NAME);

        return clientRegistrationRepository.findByRegistrationId(registrationId) != null;
    }

    private void saveContinueUrl(HttpServletRequest request) {
        String continueUrl = request.getParameter(REDIRECT_URI_PARAMETER_NAME);

        if (!hasText(continueUrl)) {
            return;
        }

        if (!isAllowedOrigin(continueUrl)) {
            return;
        }

        request
                .getSession()
                .setAttribute(REDIRECT_URI_PARAMETER_NAME, continueUrl);
    }

    private boolean isAllowedOrigin(String continueUrl) {
        for (String allowOrigin : allowOrigins) {
            if (continueUrl.startsWith(allowOrigin)) {
                return true;
            }
        }

        return false;
    }

    private String trimTrailingSlash(String origin) {
        if (origin.endsWith("/")) {
            return origin.substring(0, origin.length() - 1);
        }

        return origin;
    }

}
