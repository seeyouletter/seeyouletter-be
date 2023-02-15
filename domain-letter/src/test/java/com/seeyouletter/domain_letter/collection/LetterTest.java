package com.seeyouletter.domain_letter.collection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LetterTest {

    @Test
    void instantiate() {
        // given
        String title = "청첩장";

        // when
        Letter letter = new Letter(title);

        // then
        assertThat(letter.getTitle()).isEqualTo(title);
    }

}
