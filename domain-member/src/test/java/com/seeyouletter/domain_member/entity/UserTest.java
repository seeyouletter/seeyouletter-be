package com.seeyouletter.domain_member.entity;

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
        String gender = "M";
        LocalDate birth = LocalDate.of(1996, 9, 17);

        // when
        User user = new User(email, phone, gender, birth);

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
        assertThat(user.getPhone(), is(equalTo(phone)));
        assertThat(user.getGender(), is(equalTo(gender)));
        assertThat(user.getBirth(), is(equalTo(birth)));
    }

}
