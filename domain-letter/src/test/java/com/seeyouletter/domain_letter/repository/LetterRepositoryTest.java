package com.seeyouletter.domain_letter.repository;

import com.seeyouletter.domain_letter.MongoTestContext;
import com.seeyouletter.domain_letter.collection.Letter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

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
        assertThat(letter.getTitle()).isEqualTo(title);
        assertThat(letter.getId()).isNotNull();
    }

}
