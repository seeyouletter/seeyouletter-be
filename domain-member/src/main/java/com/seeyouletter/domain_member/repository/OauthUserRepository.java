package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.OauthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OauthUserRepository extends JpaRepository<OauthUser, Long> {

    Optional<OauthUser> findByOauthId(String oauthId);
}
