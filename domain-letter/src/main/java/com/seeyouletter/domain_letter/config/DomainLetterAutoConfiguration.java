package com.seeyouletter.domain_letter.config;

import com.seeyouletter.domain_letter.collection.Letter;
import com.seeyouletter.domain_letter.repository.LetterRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.repository.config.EnableMongoRepositories;

@AutoConfiguration
@RequiredArgsConstructor
public class DomainLetterAutoConfiguration {

    @Configuration
    @EntityScan(basePackageClasses = {Letter.class})
    @EnableMongoRepositories(basePackageClasses = {LetterRepository.class})
    @RequiredArgsConstructor
    public static class MongoConfiguration {

    }

}