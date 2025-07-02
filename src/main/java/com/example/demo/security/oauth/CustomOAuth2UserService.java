package com.example.demo.security.oauth;

import com.example.demo.refresh.RefreshRepository;
import com.example.demo.security.oauth.provider.OAuth2Response;
import com.example.demo.user.User;
import com.example.demo.user.UserRepository;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final RefreshRepository refreshRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);                                                            //DefaultOAuth2User를 받아옴
        OAuth2Response oAuth2Response = OAuth2Response.of(userRequest.getClientRegistration(), oAuth2User);             //OAuth2Response => 모든 OAuth 인증 추상 객체
        Optional<User> existUser = userRepository.findByProviderId(oAuth2Response.getProviderId());
        if(existUser.isPresent()) return reLogin(existUser);
        return signIn(oAuth2Response);
    }

    private OAuth2User reLogin(Optional<User> existUser) {
        return existUser.map(user -> {
            refreshRepository.findByUser(user).ifPresent(refreshToken ->
                    refreshRepository.deleteById(refreshToken.getId())
            );
            return new DefaultOAuth2User(user.getId(), user.getRole());
        });
    }

    private DefaultOAuth2User signIn(OAuth2Response oAuth2Response) {
        User newUser = User.of(oAuth2Response);
        userRepository.save(newUser);
        return new DefaultOAuth2User(newUser.getId(), newUser.getRole());
    }
}
