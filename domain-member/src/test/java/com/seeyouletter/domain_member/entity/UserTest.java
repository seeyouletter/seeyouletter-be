package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;


class UserTest {

    @Test
    void instantiate() {
        // given
        String name = "신영진";
        String email = "dev.sinbom@gmail.com";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);

        // when
        User user = User.builder()
                .name(name)
                .email(email)
                .phone(phone)
                .genderType(genderType)
                .birth(birth)
                .regDate(LocalDateTime.now())
                .build();

        // then
        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.getPhone()).isEqualTo(phone);
        assertThat(user.getGenderType()).isEqualTo(genderType);
        assertThat(user.getBirth()).isEqualTo(birth);
    }

}
