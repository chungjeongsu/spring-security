package com.ureca.juksoon.global.security.oauth.response;

import java.util.Map;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class KakaoResponse implements OAuth2Response{
    private static final String KAKAO_PROVIDER = "Kakao";
    private final Map<String, Object> attributes;

    @Override
    public String getProvider() {
        return KAKAO_PROVIDER;
    }

    @Override
    public String getProviderId() {
        return attributes.get(Scope.KAKAO_ID_SCOPE.getScopeKey()).toString();
    }

    @Override
    public String getEmail() {
        @SuppressWarnings("unchecked")
        Map<String, Object> account = (Map<String,Object>) attributes.get(Scope.KAKAO_ACCOUNT_SCOPE.getScopeKey());
        return account.get(Scope.KAKAO_EMAIL_SCOPE.getScopeKey()).toString();
    }

    @Override
    public String getName() {
        @SuppressWarnings("unchecked")
        Map<String, Object> properties = (Map<String, Object>) attributes.get(Scope.KAKAO_PROPERTY_SCOPE.getScopeKey());
        return properties.get(Scope.KAKAO_NAME_SCOPE.getScopeKey()).toString();
    }
}
