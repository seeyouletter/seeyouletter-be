package com.seeyouletter.api_member.auth.config;

import com.seeyouletter.domain_member.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Map;

public class PrincipalDetails implements UserDetails, OAuth2User {

    private static final long serialVersionUID = 1L;

    private final User user;

    private final Map<String, Object> attributes;


    public PrincipalDetails(User user){
        this.user = user;
        this.attributes = null;
    }

    public PrincipalDetails(User user, Map<String, Object> attributes){
        this.user = user;
        this.attributes = attributes;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public String getName() {
        return String.valueOf(user.getId());
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
