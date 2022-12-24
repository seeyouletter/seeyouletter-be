package com.seeyouletter.api_letter;

import com.seeyouletter.domain_member.entity.User;
import com.seeyouletter.domain_member.repository.UserRepository;
import com.seeyouletter.domain_letter.collection.Letter;
import com.seeyouletter.domain_letter.repository.LetterRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ApiLetterApplicationTest extends IntegrationTestContext {

    @Autowired
    private LetterRepository letterRepository;

    @Autowired
    private UserRepository usersRepository;

    @Test
    void contextLoads() {
        Letter letter = new Letter("청첩장");
        letterRepository.save(letter);

        User user = new User("dev.sinbom@gmail.com");
        usersRepository.save(user);
    }

}
