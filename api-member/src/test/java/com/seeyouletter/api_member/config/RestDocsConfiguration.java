package com.seeyouletter.api_member.config;

import org.springframework.boot.test.autoconfigure.restdocs.RestDocsMockMvcConfigurationCustomizer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.restdocs.mockmvc.RestDocumentationResultHandler;
import org.springframework.restdocs.snippet.Snippet;
import org.springframework.web.filter.CharacterEncodingFilter;

import static org.springframework.http.HttpHeaders.*;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.document;
import static org.springframework.restdocs.operation.preprocess.Preprocessors.*;

@TestConfiguration
public class RestDocsConfiguration {

    @Bean
    public CharacterEncodingFilter characterEncodingFilter() {
        return new CharacterEncodingFilter("UTF-8", true);
    }

    @Bean
    public RestDocsMockMvcConfigurationCustomizer restDocsMockMvcConfigurationCustomizer() {
        return configurer -> configurer
                .operationPreprocessors()
                .withRequestDefaults(
                        prettyPrint(),
                        removeHeaders(
                                "X-Forwarded-Host",
                                "X-Forwarded-Proto",
                                CONTENT_LENGTH
                        ),
                        modifyUris()
                                .scheme("https")
                                .host("dev-member.seeyouletter.kr")
                                .removePort(),
                        modifyParameters()
                                .remove("_csrf")
                )
                .withResponseDefaults(
                        prettyPrint(),
                        removeHeaders(
                                "X-Content-Type-Options",
                                "X-XSS-Protection",
                                "X-Frame-Options",
                                "Pragma",
                                VARY,
                                CACHE_CONTROL,
                                EXPIRES,
                                CONTENT_LENGTH
                        )
                );
    }

    public static RestDocumentationResultHandler defaultDocument(Snippet... snippets) {
        return document("{class-name}/{method-name}", snippets);
    }

}
