package com.seeyouletter.api_member.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import static java.util.Arrays.asList;
import static java.util.Collections.singletonList;

@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .oauth2Login();

        return httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource())
                .and()
                .authorizeRequests()
                .mvcMatchers("/authorized").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .defaultSuccessUrl("/")
                .usernameParameter("email")
                .and()
                .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User
                .withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(user);
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
                        "https://seeyouletter.kr"
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
