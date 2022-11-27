package com.seeyouletter.domain_sample2.repository;

import com.seeyouletter.domain_sample2.MongoTestContext;
import com.seeyouletter.domain_sample2.collection.Letter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

class LetterRepositoryTest extends MongoTestContext {

    @Autowired
    private LetterRepository letterRepository;

    @Test
    void test() {
        // given
        String title = "청첩장";
        Letter letter = new Letter(title);

        // when
        letterRepository.save(letter);

        // then
        assertThat(letter.getTitle(), is(equalTo(title)));
        assertThat(letter.getId(), is(notNullValue()));
    }

}
