package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.enums.GenderType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    User createUser(){
        String email = "dev.sinbom@gmail.com";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);

        return new User(email, phone, genderType, birth);
    }
    @Test
    void save() {
        // given
        User user = createUser();

        // when
        User savedUser = userRepository.save(user);

        // then
        assertThat(savedUser.getEmail(), is(equalTo(user.getEmail())));
        assertThat(savedUser.getPhone(), is(equalTo(user.getPhone())));
        assertThat(savedUser.getGenderType(), is(equalTo(user.getGenderType())));
        assertThat(savedUser.getBirth(), is(equalTo(user.getBirth())));
        assertThat(savedUser.getId(), is(notNullValue()));
    }

    @Test
    void findById() {
        // given
        User savedUser = userRepository.save(createUser());

        // when
        User foundUser = userRepository.findById(savedUser.getId()).get();

        // then
        assertThat(savedUser.getEmail(), is(equalTo(foundUser.getEmail())));
    }

}
