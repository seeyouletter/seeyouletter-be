package com.seeyouletter.api_member.auth.config;

import com.fasterxml.jackson.annotation.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY;
import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE;
import static com.fasterxml.jackson.annotation.JsonTypeInfo.Id.CLASS;

@JsonTypeInfo(use = CLASS)
@JsonAutoDetect(
        fieldVisibility = ANY,
        getterVisibility = NONE,
        isGetterVisibility = NONE
)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class CustomOauth2UserMixIn {

    @JsonCreator
    CustomOauth2UserMixIn(@JsonProperty(value = "authorities") Collection<? extends GrantedAuthority> authorities,
                          @JsonProperty(value = "attributes") Map<String, Object> attributes,
                          @JsonProperty(value = "username") String username) {
    }

}
