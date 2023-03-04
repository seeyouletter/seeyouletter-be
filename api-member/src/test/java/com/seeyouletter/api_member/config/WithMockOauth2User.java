package com.seeyouletter.api_member.config;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Documented;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.springframework.security.test.context.support.TestExecutionEvent.TEST_METHOD;

@Target(value = {METHOD, TYPE})
@Retention(value = RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithMockOauth2UserSecurityContextFactory.class)
public @interface WithMockOauth2User {

    String value() default "user";

    String username() default "";

    String[] roles() default {"USER"};

    String[] authorities() default {};

    String clientRegistrationId() default "client";

    AttributeKeyPair[] attributes() default {};

    @AliasFor(annotation = WithSecurityContext.class)
    TestExecutionEvent setupBefore() default TEST_METHOD;

    @interface AttributeKeyPair {

        String key();

        String value();

    }

}
