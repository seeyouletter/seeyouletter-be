package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.enums.converter.GenderTypeConverter;
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

    @Column(nullable = false)
    @Convert(converter = GenderTypeConverter.class)
    private GenderType genderType;

    @Column(nullable = false)
    private LocalDate birth;

    @Column(length = 200, nullable = true)
    private String howJoin;

    @Column(nullable = true)
    private LocalDate regDate;

    @Column(nullable = true)
    private LocalDate lastAccess;

    public User(String email, String phone, GenderType genderType, LocalDate birth) {
        this.email = email;
        this.phone = phone;
        this.genderType = genderType;
        this.birth = birth;
    }

}
