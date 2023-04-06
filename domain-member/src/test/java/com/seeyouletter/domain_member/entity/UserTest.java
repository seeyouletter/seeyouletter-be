package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;


class UserTest {

    @Test
    void instantiate() {
        // given
        String name = "신영진";
        String email = "dev.sinbom@gmail.com";
        String password = "1234!@#$";
        String profileImage = "https://www.test.com/image/me";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);
        String howJoin = "테스트";

        // when
        User user = User.builder()
                .name(name)
                .email(email)
                .password(password)
                .profileImage(profileImage)
                .phone(phone)
                .genderType(genderType)
                .birth(birth)
                .howJoin(howJoin)
                .build();

        // then
        assertThat(user.getName()).isEqualTo(name);
        assertThat(user.getEmail()).isEqualTo(email);
        assertThat(user.getPassword()).isEqualTo(password);
        assertThat(user.getProfileImage()).isEqualTo(profileImage);
        assertThat(user.getPhone()).isEqualTo(phone);
        assertThat(user.getGenderType()).isEqualTo(genderType);
        assertThat(user.getBirth()).isEqualTo(birth);
        assertThat(user.getHowJoin()).isEqualTo(howJoin);
        assertThat(user.getRegDate()).isNull();
        assertThat(user.getLastAccess()).isNull();
    }

}
