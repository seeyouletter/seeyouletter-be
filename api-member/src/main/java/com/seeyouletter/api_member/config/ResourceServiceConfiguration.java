package com.seeyouletter.api_member.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServiceConfiguration {

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity httpSecurity,
                                                                 CorsConfigurationSource corsConfigurationSource) throws Exception {
        httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource)
                .and()
                .requestMatchers()
                .mvcMatchers("/api/**")
                .and()
                .oauth2ResourceServer()
                .jwt();

        return httpSecurity.build();
    }

}
