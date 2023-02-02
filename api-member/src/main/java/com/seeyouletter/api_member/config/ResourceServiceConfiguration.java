package com.seeyouletter.api_member.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ResourceServiceConfiguration {

    @Bean
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .requestMatchers()
                .mvcMatchers("/api/**")
                .and()
                .oauth2ResourceServer()
                .jwt();

        return httpSecurity.build();
    }

}
