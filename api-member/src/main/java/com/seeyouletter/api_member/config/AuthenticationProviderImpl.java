package com.seeyouletter.api_member.config;

import com.seeyouletter.api_member.auth.config.PrincipalDetails;
import com.seeyouletter.api_member.auth.service.UserDetailsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class AuthenticationProviderImpl implements AuthenticationProvider {

    private final UserDetailsServiceImpl userDetailsService;

    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String email = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        PrincipalDetails user = (PrincipalDetails) userDetailsService.loadUserByUsername(email);

        if(!passwordEncoder.matches(password, user.getPassword())){
            throw new BadCredentialsException("wrong password");
        }

        return new UsernamePasswordAuthenticationToken(email, password, user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return true;
    }
}
