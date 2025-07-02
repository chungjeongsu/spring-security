package com.example.demo.security.oauth.provider.kakao;

import com.example.demo.security.oauth.provider.OAuth2Response;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * {
 *   "id": 123456789,
 *   "connected_at": "2023-07-02T09:24:32Z",
 *   "properties": {
 *     "nickname": "홍길동"
 *   },
 *   "kakao_account": {
 *     "profile_nickname_needs_agreement": false,
 *     "profile": {
 *       "nickname": "홍길동"
 *     },
 *     "has_email": true,
 *     "email_needs_agreement": false,
 *     "is_email_valid": true,
 *     "is_email_verified": true,
 *     "email": "hong@kakao.com"
 *   }
 * }
 */

public class KakaoResponse extends OAuth2Response {
    public KakaoResponse(OAuth2User oAuth2User) {
        super(oAuth2User);
    }

    @Override
    protected String getProvider() {
        return "kakao";
    }

    @Override
    protected String getProviderId() {
        if(super.oauth2User.getAttribute("id") == null) throw new AuthenticationServiceException("provider id가 없음");
        return String.valueOf(super.oauth2User.getAttributes().get("id"));
    }

    @Override
    protected String getEmail() {
        Map<String, Object> attributes = super.oauth2User.getAttributes();
        if(attributes == null) throw new AuthenticationServiceException("email이 없음");
        return (String) attributes.get("email");
    }

    @Override
    protected String getName() {
        Map<String, Object> properties = super.oauth2User.getAttribute("properties");
        if (properties == null) throw new AuthenticationServiceException("nickname이 없음");
        return (String) properties.get("nickname");
    }
}
