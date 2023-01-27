package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.enums.converter.GenderTypeConverter;
import com.sun.istack.NotNull;
import lombok.*;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotNull
    @Column(length = 50, nullable = false)
    private String name;

    @NotNull
    @Column(length = 50, nullable = false)
    private String email;

    private String profileImage;

    @Column(length = 20)
    private String password;

    @Column(length = 15)
    private String phone;

    @NotNull
    @Column(nullable = false)
    @Convert(converter = GenderTypeConverter.class)
    private GenderType genderType;

    private LocalDate birth;

    @Column(length = 200)
    private String howJoin;

    private LocalDateTime regDate;

    private LocalDateTime lastAccess;

}
