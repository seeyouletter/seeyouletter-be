package com.seeyouletter.domain_member.entity;

import com.seeyouletter.domain_member.enums.OauthType;
import com.seeyouletter.domain_member.enums.converter.OauthTypeConverter;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import javax.persistence.*;

import static javax.persistence.GenerationType.IDENTITY;
import static lombok.AccessLevel.PROTECTED;

@Getter
@Entity
@Table(name = "oauth_user")
@NoArgsConstructor(access = PROTECTED)
@EntityListeners(AuditingEntityListener.class)
public class OauthUser {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    @Column(name = "oauth_id", nullable = false, unique = true)
    private String oauthId;

    @Convert(converter = OauthTypeConverter.class)
    @Column(name = "provider", nullable = false)
    private OauthType provider;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    public OauthUser(String oauthId, OauthType provider, User user) {
        this.oauthId = oauthId;
        this.provider = provider;
        this.user = user;
    }

}
