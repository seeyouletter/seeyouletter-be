package com.seeyouletter.api_letter;

import com.seeyouletter.domain_member.entity.Users;
import com.seeyouletter.domain_member.repository.UsersRepository;
import com.seeyouletter.domain_letter.collection.Letter;
import com.seeyouletter.domain_letter.repository.LetterRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ApiLetterApplicationTest extends IntegrationTestContext {

    @Autowired
    private LetterRepository letterRepository;

    @Autowired
    private UsersRepository usersRepository;

    @Test
    void contextLoads() {
        Letter letter = new Letter("청첩장");
        letterRepository.save(letter);

        Users user = new Users("dev.sinbom@gmail.com");
        usersRepository.save(user);
    }

}
