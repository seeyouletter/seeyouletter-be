package com.seeyouletter.api_member.config;

import com.seeyouletter.api_member.service.UserService;
import com.seeyouletter.domain_member.entity.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Map;

import static org.springframework.security.oauth2.core.oidc.StandardClaimNames.PHONE_NUMBER_VERIFIED;
import static org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames.ID_TOKEN;
import static org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN;
import static org.springframework.util.StringUtils.hasText;

@Component
@RequiredArgsConstructor
public class CustomOauth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private final UserService userService;

    @Override
    public void customize(JwtEncodingContext context) {
        JwtClaimsSet.Builder claims = context.getClaims();

        String email = context
                .getPrincipal()
                .getName();

        if (context.getTokenType().equals(ACCESS_TOKEN)) {
            claims.claim("sub", email);

            return;
        }

        if (context.getTokenType().getValue().equals(ID_TOKEN)) {
            User user = userService.findByEmail(email);

            Map<String, Object> oidcClaims = OidcUserInfo
                    .builder()
                    .subject(user.getEmail())
                    .preferredUsername(email) // TODO 사용되는 이름으로 변경
                    .name(user.getName())
                    .nickname(user.getName()) // TODO 닉네임으로 변경
                    .profile(getProfile(user))
                    .birthdate(getBirthdate(user))
                    .gender(user.getGenderType().name())
                    .email(user.getEmail())
                    .emailVerified(getEmailVerified(user))
                    .phoneNumber(getPhone(user))
                    .claim(PHONE_NUMBER_VERIFIED, getPhoneVerified(user))
                    .build()
                    .getClaims();

            claims.claims(i -> i.putAll(oidcClaims));
        }
    }

    private String getBirthdate(User user) {
        if (user.getBirth() == null) {
            return null;
        }

        return user
                .getBirth()
                .toString();
    }

    private String getPhone(User user) {
        if (!hasText(user.getPhone())) {
            return null;
        }

        return user.getPhone();
    }

    private boolean getPhoneVerified(User user) {
        if (!hasText(user.getPhone())) {
            return false;
        }

        // TODO 휴대폰 검증 여부 판단은 추후 비즈니스 로직에 따라 다를 수 있음
        return true;
    }

    private boolean getEmailVerified(User user) {
        // TODO 이메일 검증 여부 판단은 추후 비즈니스 로직에 따라 다를 수 있음
        return true;
    }

    private String getProfile(User user) {
        if (!hasText(user.getProfileImage())) {
            // TODO 기본 이미지 프로필 설정
            return "https://url.kr/e7imr8";
        }

        return user.getProfileImage();
    }

}
