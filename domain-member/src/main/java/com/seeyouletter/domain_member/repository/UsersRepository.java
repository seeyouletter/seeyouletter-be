package com.seeyouletter.domain_member.repository;

import com.seeyouletter.domain_member.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsersRepository extends JpaRepository<Users, Long> {

}
