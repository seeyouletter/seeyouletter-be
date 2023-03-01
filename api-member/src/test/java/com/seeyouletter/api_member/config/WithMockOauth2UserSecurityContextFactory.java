package com.seeyouletter.api_member.config;

import com.seeyouletter.api_member.auth.config.CustomOAuth2User;
import com.seeyouletter.api_member.config.WithMockOauth2User.AttributeKeyPair;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Arrays.asList;
import static java.util.stream.Collectors.toList;
import static org.springframework.util.StringUtils.hasLength;

public class WithMockOauth2UserSecurityContextFactory implements WithSecurityContextFactory<WithMockOauth2User> {

    @Override
    public SecurityContext createSecurityContext(WithMockOauth2User withUser) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();

        context.setAuthentication(createAuthentication(withUser));

        return context;
    }

    private String getUsername(WithMockOauth2User withUser) {
        if (hasLength(withUser.username())) {
            return withUser.username();
        }

        Assert.notNull(withUser.value(), () -> withUser + " cannot have null username on both username and value properties");

        return withUser.value();
    }

    private List<GrantedAuthority> createGrantedAuthorities(WithMockOauth2User withUser) {
        List<GrantedAuthority> grantedAuthorities = Arrays
                .stream(withUser.authorities())
                .map(SimpleGrantedAuthority::new)
                .collect(toList());

        if (grantedAuthorities.isEmpty()) {
            for (String role : withUser.roles()) {
                Assert.isTrue(!role.startsWith("ROLE_"), () -> "roles cannot start with ROLE_ Got " + role);

                grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + role));
            }
        }

        return grantedAuthorities;
    }

    private Map<String, Object> createAttributes(WithMockOauth2User withUser) {
        Map<String, Object> attributes = Arrays
                .stream(withUser.attributes())
                .collect(
                        Collectors.toMap(
                                AttributeKeyPair::key,
                                AttributeKeyPair::value
                        )
                );

        if (attributes.isEmpty()) {
            attributes.put("id", getUsername(withUser));
        }

        return attributes;
    }

    private Authentication createAuthentication(WithMockOauth2User withUser) {
        if (!(withUser.roles().length == 1 && "USER".equals(withUser.roles()[0]))) {
            throw new IllegalStateException("You cannot define roles attribute " + asList(withUser.roles())
                    + " with authorities attribute " + asList(withUser.authorities()));
        }

        List<GrantedAuthority> grantedAuthorities = createGrantedAuthorities(withUser);
        CustomOAuth2User customOAuth2User = new CustomOAuth2User(grantedAuthorities, createAttributes(withUser), getUsername(withUser));

        return new OAuth2AuthenticationToken(customOAuth2User, grantedAuthorities, withUser.clientRegistrationId());
    }


}
