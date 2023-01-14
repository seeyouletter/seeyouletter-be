package com.seeyouletter.domain_member.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

@Getter
@AllArgsConstructor
public enum OauthType {

    KAKAO("kakao"),
    NAVER("naver");

    private final String type;

    public static OauthType find(String code){
        return Arrays.stream(OauthType.values())
                .filter(x->x.getType().equals(code))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("잘못된 성별타입 입니다."));
    }

}
