package com.seeyouletter.domain_member.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class UserTest {

    @Test
    void instantiate() {
        // given
        String email = "dev.sinbom@gmail.com";

        // when
        User user = new User(email, phone, gender, birth);

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
    }

}
