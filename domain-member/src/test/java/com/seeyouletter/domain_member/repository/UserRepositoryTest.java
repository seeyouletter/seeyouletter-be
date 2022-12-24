package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    void save() {
        // given
        String email = "dev.sinbom@gmail.com";
        User user = new User(email);

        // when
        userRepository.save(user);

        // then
        assertThat(user.getEmail(), is(equalTo(email)));
        assertThat(user.getId(), is(notNullValue()));
    }

}
