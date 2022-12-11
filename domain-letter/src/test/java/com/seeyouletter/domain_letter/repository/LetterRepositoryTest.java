package com.seeyouletter.domain_letter.repository;

import com.seeyouletter.domain_letter.MongoTestContext;
import com.seeyouletter.domain_letter.collection.Letter;
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
