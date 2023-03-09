package com.seeyouletter.api_member.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeyouletter.api_member.auth.config.Oauth2ClientAuthorizationRequestSaveContinueUrlFilter;
import com.seeyouletter.api_member.auth.config.RestAuthenticationProcessingFilter;
import com.seeyouletter.api_member.auth.config.RestLoginHttpConfigurer;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private static final List<String> FIRST_PARTY_CLIENT_ORIGINS = asList(
            "http://localhost:2462",
            "http://127.0.0.1:2462",
            "https://seeyouletter.kr",
            "https://www.seeyouletter.kr"
    );

    private final ObjectMapper objectMapper;

    private final ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        applyOauth2ClientSecurity(httpSecurity);

        httpSecurity
                .apply(new RestLoginHttpConfigurer(objectMapper));

        httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .csrf()
                .ignoringAntMatchers(RestAuthenticationProcessingFilter.REST_LOGIN_PATTERN)
                .and()
                .authorizeRequests()
                .mvcMatchers("/authorized").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/form/login")
                .usernameParameter("email");

        return httpSecurity.build();
    }

    private void applyOauth2ClientSecurity(HttpSecurity http) throws Exception {
        http
                .oauth2Login()
                .successHandler(new Oauth2ClientRedirectContinueUrlAuthenticationSuccessHandler())
                .failureHandler(new Oauth2ClientRedirectContinueUrlAuthenticationFailureHandler())
                .and()
                .addFilterBefore(
                        new Oauth2ClientAuthorizationRequestSaveContinueUrlFilter(
                                clientRegistrationRepository,
                                FIRST_PARTY_CLIENT_ORIGINS
                        ),
                        OAuth2AuthorizationRequestRedirectFilter.class
                );
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedHeaders(singletonList("*"));
        configuration.setAllowedMethods(singletonList("*"));
        configuration.setExposedHeaders(singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(FIRST_PARTY_CLIENT_ORIGINS);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
