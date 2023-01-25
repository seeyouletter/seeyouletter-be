package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.OauthType;
import com.seeyouletter.domain_member.enums.converter.OauthTypeConverter;
import com.sun.istack.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;

@Getter
@Entity
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class OauthUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true)
    private String oauthId;

    @NotNull
    @Column(nullable = false)
    @Convert(converter = OauthTypeConverter.class)
    private OauthType provider;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="user_id")
    private User user;

}
