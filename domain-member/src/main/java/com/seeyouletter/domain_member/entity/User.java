package com.seeyouletter.domain_member.entity;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.time.LocalDate;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 50, nullable = false)
    private String email;

    @Column(length = 20, nullable = true)
    private String password;

    @Column(length = 15, nullable = true)
    private String phone;

    @Column(length = 1, nullable = false)
    private String gender;

    @Column(nullable = false)
    private LocalDate birth;

    @Column(length = 200, nullable = true)
    private String howJoin;

    @Column(nullable = true)
    private LocalDate regDate;

    @Column(nullable = true)
    private LocalDate lastAccess;

    public User(String email, String phone, String gender, LocalDate birth) {
        this.email = email;
        this.phone = phone;
        this.gender = gender;
        this.birth = birth;
    }

}
