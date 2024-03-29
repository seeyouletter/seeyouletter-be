package com.seeyouletter.api_member.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;

import static java.security.KeyPairGenerator.getInstance;
import static java.util.UUID.randomUUID;
import static org.springframework.core.Ordered.HIGHEST_PRECEDENCE;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.NONE;
import static org.springframework.security.oauth2.core.oidc.OidcScopes.*;
import static org.springframework.security.oauth2.server.authorization.client.RegisteredClient.withId;
import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration.applyDefaultSecurity;

@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

    @Bean
    @Order(value = HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity httpSecurity,
                                                                      CorsConfigurationSource corsConfigurationSource) throws Exception {
        applyDefaultSecurity(httpSecurity);

        return httpSecurity
                .cors()
                .configurationSource(corsConfigurationSource)
                .and()
                .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(withDefaults())
                .and()
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
                .formLogin(withDefaults())
                .build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        Set<String> allowedOidcScopes = Set.of(OPENID, PROFILE, EMAIL, ADDRESS, PHONE);
        Set<String> allowedCustomScopes = Set.of("user.read", "user.write");
        Set<String> allowedRedirectUris = Set.of("http://127.0.0.1:8600/authorized", "https://dev-member.seeyouletter.kr/authorized");


        RegisteredClient registeredClient = withId("98348f89-5433-41a1-b12d-657f4f3d19f9")
                .clientId("seeyouletter")
                .clientAuthenticationMethod(NONE)
                .authorizationGrantType(AUTHORIZATION_CODE)
                .redirectUris(redirectUris -> redirectUris.addAll(allowedRedirectUris))
                .scopes(scopes -> {
                    scopes.addAll(allowedOidcScopes);
                    scopes.addAll(allowedCustomScopes);
                })
                .clientSettings(
                        ClientSettings
                                .builder()
                                .requireProofKey(true)
                                .requireAuthorizationConsent(false)
                                .build()
                )
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(StringRedisTemplate stringRedisTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new RedisOauth2AuthorizationService(stringRedisTemplate, registeredClientRepository);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    private static RSAKey generateRsa() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey
                .Builder(publicKey)
                .privateKey(privateKey)
                .keyID(randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = getInstance("RSA");

            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings
                .builder()
                .build();
    }

}
