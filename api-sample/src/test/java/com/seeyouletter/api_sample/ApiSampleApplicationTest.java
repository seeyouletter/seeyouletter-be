package com.seeyouletter.api_sample;

import com.seeyouletter.domain_sample.entity.Users;
import com.seeyouletter.domain_sample.repository.UsersRepository;
import com.seeyouletter.domain_sample2.collection.Letter;
import com.seeyouletter.domain_sample2.repository.LetterRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

class ApiSampleApplicationTest extends IntegrationTestContext {

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
