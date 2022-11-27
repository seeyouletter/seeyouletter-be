package com.seeyouletter.domain_sample.repository;

import com.seeyouletter.domain_sample.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsersRepository extends JpaRepository<Users, Long> {

}
