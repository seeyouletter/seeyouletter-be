package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.enums.GenderType;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    User createUser() {
        String name = "신영진";
        String email = "dev.sinbom@gmail.com";
        String password = "1234!@#$";
        String profileImage = "https://www.test.com/image/me";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);
        String howJoin = "테스트";

        return User.builder()
                .name(name)
                .email(email)
                .password(password)
                .profileImage(profileImage)
                .phone(phone)
                .genderType(genderType)
                .birth(birth)
                .howJoin(howJoin)
                .build();
    }

    @Test
    void save() {
        // given
        User user = createUser();

        // when
        User savedUser = userRepository.save(user);

        // then
        assertThat(savedUser.getName()).isEqualTo(user.getName());
        assertThat(savedUser.getEmail()).isEqualTo(user.getEmail());
        assertThat(savedUser.getPassword()).isEqualTo(user.getPassword());
        assertThat(savedUser.getProfileImage()).isEqualTo(user.getProfileImage());
        assertThat(savedUser.getPhone()).isEqualTo(user.getPhone());
        assertThat(savedUser.getGenderType()).isEqualTo(user.getGenderType());
        assertThat(savedUser.getBirth()).isEqualTo(user.getBirth());
        assertThat(savedUser.getHowJoin()).isEqualTo(user.getHowJoin());
        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getRegDate()).isNotNull();
        assertThat(savedUser.getLastAccess()).isNotNull();
    }

    @Test
    void findById() {
        // given
        User savedUser = userRepository.save(createUser());

        // when
        User foundUser = userRepository.findById(savedUser.getId())
                .orElseThrow();

        // then
        assertThat(foundUser.getName()).isEqualTo(savedUser.getName());
        assertThat(foundUser.getEmail()).isEqualTo(savedUser.getEmail());
        assertThat(foundUser.getPassword()).isEqualTo(savedUser.getPassword());
        assertThat(foundUser.getProfileImage()).isEqualTo(savedUser.getProfileImage());
        assertThat(foundUser.getPhone()).isEqualTo(savedUser.getPhone());
        assertThat(foundUser.getGenderType()).isEqualTo(savedUser.getGenderType());
        assertThat(foundUser.getBirth()).isEqualTo(savedUser.getBirth());
        assertThat(foundUser.getHowJoin()).isEqualTo(savedUser.getHowJoin());
        assertThat(foundUser.getId()).isEqualTo(savedUser.getId());
        assertThat(foundUser.getRegDate()).isEqualTo(savedUser.getRegDate());
        assertThat(foundUser.getLastAccess()).isEqualTo(savedUser.getLastAccess());
    }

}
