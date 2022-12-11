package com.seeyouletter.domain_member.config;

import com.querydsl.jpa.impl.JPAQueryFactory;
import com.seeyouletter.domain_member.entity.Users;
import com.seeyouletter.domain_member.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import javax.persistence.EntityManager;

@AutoConfiguration
@RequiredArgsConstructor
public class DomainMemberAutoConfiguration {

    @Configuration
    @EntityScan(basePackageClasses = {Users.class})
    @EnableJpaRepositories(basePackageClasses = {UsersRepository.class})
    @RequiredArgsConstructor
    public static class JpaConfiguration {

        private final EntityManager entityManager;

        @Bean
        public JPAQueryFactory jpaQueryFactory() {
            return new JPAQueryFactory(entityManager);
        }

    }

}
