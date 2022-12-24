package com.seeyouletter.api_letter;

import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.repository.UserRepository;
import com.seeyouletter.domain_letter.collection.Letter;
import com.seeyouletter.domain_letter.repository.LetterRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Date;

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
        String gender = "W";
        Date birth = new Date(System.currentTimeMillis());

        User user = new User(email, phone, gender, birth);
        usersRepository.save(user);
    }

}
