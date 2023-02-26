package com.seeyouletter.api_member.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static com.seeyouletter.api_member.auth.config.CustomHttpConfigurer.customHttpConfigurer;
import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {

    private final ObjectMapper objectMapper;

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .oauth2Login();

        httpSecurity
                .apply(customHttpConfigurer(objectMapper));

        httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .csrf()
                .ignoringAntMatchers("/login")
                .and()
                .authorizeRequests()
                .mvcMatchers("/authorized").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/form/login")
                .defaultSuccessUrl("/")
                .usernameParameter("email");

        return httpSecurity.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedHeaders(singletonList("*"));
        configuration.setAllowedMethods(singletonList("*"));
        configuration.setExposedHeaders(singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedOrigins(
                asList(
                        "http://localhost:2462",
                        "http://127.0.0.1:9600",
                        "http://127.0.0.1:2462",
                        "https://seeyouletter.kr",
                        "https://www.seeyouletter.kr"
                )
        );

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
