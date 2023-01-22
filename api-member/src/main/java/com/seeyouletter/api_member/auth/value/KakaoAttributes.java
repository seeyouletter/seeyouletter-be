package com.seeyouletter.api_member.auth.value;


import com.seeyouletter.domain_member.entity.OauthUser;
import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.enums.OauthType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class KakaoAttributes implements OauthAttributes{

    private Long id;

    private String connectedAt;

    private LinkedHashMap<String, String> properties;

    private LinkedHashMap<String, Object> kakaoAccount;

    @Override
    public OauthUser convertOauthUser() {
        User user = User.builder()
                .name(properties.get("nickname"))
                .email((String) kakaoAccount.get("email"))
                .profileImage(properties.get("profile_image"))
                .genderType(GenderType.findKakao((String) kakaoAccount.get("gender")))
                .regDate(LocalDateTime.now())
                .lastAccess(LocalDateTime.now())
                .build();

        return new OauthUser(
            null,
            Long.toString(id),
            OauthType.KAKAO,
            user
        );
    }
}