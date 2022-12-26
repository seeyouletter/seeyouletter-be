package com.seeyouletter.api_letter;

import com.seeyouletter.domain_letter.collection.Letter;
import com.seeyouletter.domain_letter.repository.LetterRepository;
import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.time.LocalDate;

class ApiLetterApplicationTest extends IntegrationTestContext {

    @Autowired
    private LetterRepository letterRepository;

    @Autowired
    private UserRepository usersRepository;

    @Test
    void contextLoads() {
        Letter letter = new Letter("청첩장");
        letterRepository.save(letter);

        String email = "dev.sinbom@gmail.com";
        String phone = "01011111111";
        GenderType genderType = GenderType.MALE;
        LocalDate birth = LocalDate.of(1996, 9, 17);

        User user = new User(email, phone, genderType, birth);
        usersRepository.save(user);
    }

}
