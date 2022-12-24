package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

}
