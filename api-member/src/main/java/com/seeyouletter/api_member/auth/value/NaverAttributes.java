package com.seeyouletter.api_member.auth.value;

import com.seeyouletter.domain_member.entity.OauthUser;
import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.enums.OauthType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class NaverAttributes implements OauthAttributes{

    private String resultCode;

    private String message;

    private Map<String, String> response;

    @Override
    public OauthUser convertOauthUser() {
        User user = User.builder()
                .name(response.get("name"))
                .email(response.get("email"))
                .phone(response.get("mobile").replace("-", ""))
                .genderType(GenderType.find(response.get("gender")))
                .regDate(LocalDateTime.now())
                .lastAccess(LocalDateTime.now())
                .build();

        return new OauthUser(
                null,
                response.get("id"),
                OauthType.NAVER,
                user
        );
    }
}
