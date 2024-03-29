package com.seeyouletter.domain_member.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

@Getter
@AllArgsConstructor
public enum GenderType {
    MALE("M"),
    FEMALE("F");

    private final String type;

    public static GenderType find(String code){
        return Arrays.stream(GenderType.values())
                .filter(x->x.getType().equals(code))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException("잘못된 성별타입 입니다."));
    }

}
