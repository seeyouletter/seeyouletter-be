package com.seeyouletter.api_member.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableMethodSecurity
public class ResourceServiceConfiguration {

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity httpSecurity,
                                                                 CorsConfigurationSource corsConfigurationSource) throws Exception {
        httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource)
                .and()
                .securityMatchers()
                .requestMatchers("/api/**")
                .and()
                .oauth2ResourceServer()
                .jwt();

        return httpSecurity.build();
    }

}
