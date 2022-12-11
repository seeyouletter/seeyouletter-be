package com.seeyouletter.domain_letter.repository;

import com.seeyouletter.domain_letter.collection.Letter;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface LetterRepository extends MongoRepository<Letter, String>, LetterRepositoryCustom {
}
