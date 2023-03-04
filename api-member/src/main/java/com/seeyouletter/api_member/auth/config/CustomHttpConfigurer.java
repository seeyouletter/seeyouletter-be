package com.seeyouletter.api_member.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

public class CustomHttpConfigurer extends AbstractHttpConfigurer<CustomHttpConfigurer, HttpSecurity> {

    private final ObjectMapper objectMapper;

    public CustomHttpConfigurer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        RestAuthenticationProcessingFilter newFilter = new RestAuthenticationProcessingFilter(authenticationManager, objectMapper);
        newFilter.setAuthenticationSuccessHandler(new RestLoginSuccessHandler());
        newFilter.setAuthenticationFailureHandler(new RestLoginFailureHandler());
        http.addFilterBefore(newFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
