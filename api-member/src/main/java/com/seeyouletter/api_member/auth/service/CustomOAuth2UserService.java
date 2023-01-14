package com.seeyouletter.api_member.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seeyouletter.api_member.auth.value.KakaoAttributes;
import com.seeyouletter.api_member.auth.value.NaverAttributes;
import com.seeyouletter.api_member.auth.value.OauthAttributes;
import com.seeyouletter.domain_member.enums.OauthType;
import com.seeyouletter.domain_member.entity.OauthUser;
import com.seeyouletter.domain_member.repository.OauthUserRepository;
import com.seeyouletter.domain_member.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    private final OauthUserRepository oauthUserRepository;

    private final ObjectMapper objectMapper;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        String provider = oAuth2UserRequest
                .getClientRegistration()
                .getRegistrationId();

        OauthAttributes oauthAttributes = mapToAttributes(provider, oAuth2User.getAttributes());
        assert oauthAttributes != null;

        isNewInsert(oauthAttributes.convertOauthUser());

        return oAuth2User;
    }

    private void isNewInsert(OauthUser oauthUser) {
        Optional<OauthUser> optionalOauthUser = oauthUserRepository.findByOauthId(oauthUser.getOauthId());

        if (optionalOauthUser.isPresent()) {
            return;
        }

        userRepository.save(oauthUser.getUser());
        oauthUserRepository.save(oauthUser);
    }

    private OauthAttributes mapToAttributes(String provider, Map<String, Object> attributes){
        if(OauthType.KAKAO.getType().equals(provider)){
            return objectMapper.convertValue(attributes, KakaoAttributes.class);
        }

        if(OauthType.NAVER.getType().equals(provider)){
            return objectMapper.convertValue(attributes, NaverAttributes.class);
        }

        return null;
    }
}
