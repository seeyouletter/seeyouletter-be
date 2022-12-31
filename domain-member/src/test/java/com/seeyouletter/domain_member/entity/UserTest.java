package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class UserTest {

    @Test
    void instantiate() {
        // given
        String email = "dev.sinbom@gmail.com";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);

        // when
        User user = User.builder()
                .email(email)
                .phone(phone)
                .genderType(genderType)
                .birth(birth)
                .build();

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
        assertThat(user.getPhone(), is(equalTo(phone)));
        assertThat(user.getGenderType(), is(equalTo(genderType)));
        assertThat(user.getBirth(), is(equalTo(birth)));
    }

}
