package com.seeyouletter.domain_sample.entity;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class UsersTest {

    @Test
    void instantiate() {
        // given
        String email = "dev.sinbom@gmail.com";

        // when
        Users user = new Users(email);

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
    }

}
