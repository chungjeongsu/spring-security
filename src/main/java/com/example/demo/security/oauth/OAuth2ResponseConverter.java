package com.example.demo.security.oauth;

import com.ureca.juksoon.global.security.oauth.response.KakaoResponse;
import com.ureca.juksoon.global.security.oauth.response.OAuth2Response;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

/**
 * 각 소셜 로그인의 사용자정보를 통합 Response로 바꿔주는 컨버터
 */

@Component
public class OAuth2ResponseConverter {
    private static final String KAKAO_PROVIDER = "kakao";

    public OAuth2Response convert(String registrationId, OAuth2User target) {
        OAuth2Response oAuth2Response = null;

        if(registrationId.equals(KAKAO_PROVIDER)){
            return oAuth2Response = new KakaoResponse(target.getAttributes());
        }
        return oAuth2Response;
    }
}
