package com.seeyouletter.api_member.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.seeyouletter.api_member.auth.value.KakaoAttributes;
import com.seeyouletter.api_member.auth.value.NaverAttributes;
import com.seeyouletter.api_member.auth.value.OauthAttributes;
import com.seeyouletter.api_member.auth.config.PrincipalDetails;
import com.seeyouletter.domain_member.entity.OauthUser;
import com.seeyouletter.domain_member.enums.OauthType;
import com.seeyouletter.domain_member.repository.OauthUserRepository;
import com.seeyouletter.domain_member.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    private final OauthUserRepository oauthUserRepository;

    private static final String CANNOT_FIND_PROVIDER = "cannot find provider";


    private final ObjectMapper objectMapper = new Jackson2ObjectMapperBuilder()
            .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .build();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) {

        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        String provider = oAuth2UserRequest
                .getClientRegistration()
                .getRegistrationId();

        OauthAttributes oauthAttributes = mapToAttributes(provider, oAuth2User.getAttributes());
        OauthUser oauthUser = isNewInsert(oauthAttributes.convertOauthUser());

        return new PrincipalDetails(oauthUser.getUser(), oAuth2User.getAttributes());
    }

    public OauthUser isNewInsert(OauthUser oauthUser) {
        Optional<OauthUser> optionalOauthUser = oauthUserRepository.findByOauthId(oauthUser.getOauthId());

        if (optionalOauthUser.isPresent()) {
            return optionalOauthUser.get();
        }

        userRepository.save(oauthUser.getUser());
        oauthUserRepository.save(oauthUser);
        return oauthUser;
    }

    private OauthAttributes mapToAttributes(String provider, Map<String, Object> attributes){
        if(OauthType.KAKAO.getType().equals(provider)){
            return objectMapper.convertValue(attributes, KakaoAttributes.class);
        }

        if(OauthType.NAVER.getType().equals(provider)){
            return objectMapper.convertValue(attributes, NaverAttributes.class);
        }

        OAuth2Error oauth2Error = new OAuth2Error(CANNOT_FIND_PROVIDER, "provider: " + provider, null);
        throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }
}
