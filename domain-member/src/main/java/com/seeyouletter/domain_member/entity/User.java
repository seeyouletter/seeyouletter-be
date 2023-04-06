package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.GenderType;
import com.seeyouletter.domain_member.enums.converter.GenderTypeConverter;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

import static javax.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;

@Getter
@Entity
@Table(name = "users")
@NoArgsConstructor(access = PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "name", length = 50, nullable = false)
    private String name;

    @Column(name = "email", length = 50, nullable = false, unique = true)
    private String email;

    @Column(name = "profile_image")
    private String profileImage;

    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "phone", length = 15)
    private String phone;

    @Convert(converter = GenderTypeConverter.class)
    @Column(name = "gender_type", nullable = false)
    private GenderType genderType;

    @Column(name = "birth")
    private LocalDate birth;

    @Column(name = "how_join", length = 200)
    private String howJoin;

    @CreatedDate
    @Column(name = "reg_date", updatable = false)
    private LocalDateTime regDate;

    @CreatedDate
    @Column(name = "last_access")
    private LocalDateTime lastAccess;

    @Builder
    private User(String name, String email, String profileImage, String password, String phone, GenderType genderType,
                 LocalDate birth, String howJoin) {
        this.name = name;
        this.email = email;
        this.profileImage = profileImage;
        this.password = password;
        this.phone = phone;
        this.genderType = genderType;
        this.birth = birth;
        this.howJoin = howJoin;
    }

}
