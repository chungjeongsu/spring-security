package com.example.demo.security.oauth.provider;

import com.example.demo.security.oauth.provider.kakao.KakaoResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

@RequiredArgsConstructor
public abstract class OAuth2Response {
    protected final OAuth2User oauth2User;

    public abstract String getProvider();
    public abstract String getProviderId();
    public abstract String getEmail();
    public abstract String getName();

    public static OAuth2Response of(ClientRegistration clientRegistration, OAuth2User oAuth2User) {
        switch (clientRegistration.getRegistrationId().toLowerCase()) {
//          case "google" -> {
//                return new KakaoResponse(oAuth2User);
//            }
            case "kakao" -> {
                return new KakaoResponse(oAuth2User);
            }
            default -> throw new AuthenticationServiceException("지원되지 않는 로그인입니다.");
        }
    }
}
