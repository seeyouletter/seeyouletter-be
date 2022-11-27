package com.seeyouletter.domain_sample.repository;

import com.seeyouletter.domain_sample.entity.Users;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@DataJpaTest
class UsersRepositoryTest {

    @Autowired
    private UsersRepository userRepository;

    @Test
    void save() {
        // given
        String email = "dev.sinbom@gmail.com";
        Users user = new Users(email);

        // when
        userRepository.save(user);

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
        assertThat(user.getId(), is(notNullValue()));
    }

}
