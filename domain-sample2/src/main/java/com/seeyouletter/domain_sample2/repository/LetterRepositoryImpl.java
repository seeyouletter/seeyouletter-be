package com.seeyouletter.domain_sample2.repository;

import org.springframework.data.mongodb.core.MongoTemplate;

public class LetterRepositoryImpl implements LetterRepositoryCustom {

    private final MongoTemplate mongoTemplate;

    public LetterRepositoryImpl(MongoTemplate mongoTemplate) {
        this.mongoTemplate = mongoTemplate;
    }

}
