package com.seeyouletter.domain_letter.collection;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;

class LetterTest {

    @Test
    void instantiate() {
        // given
        String title = "청첩장";

        // when
        Letter letter = new Letter(title);

        // then
        assertThat(letter.getTitle(), is(equalTo(title)));
    }

}
