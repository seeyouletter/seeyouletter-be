package com.seeyouletter.domain_sample2.repository;

import com.seeyouletter.domain_sample2.collection.Letter;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface LetterRepository extends MongoRepository<Letter, String>, LetterRepositoryCustom {
}
