package com.ureca.juksoon.global.security.oauth.response;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Scope {
    KAKAO_ID_SCOPE("id"),
    KAKAO_PROPERTY_SCOPE("properties"),
    KAKAO_NAME_SCOPE("nickname"),
    KAKAO_ACCOUNT_SCOPE("kakao_account"),
    KAKAO_EMAIL_SCOPE("email");
    private final String scopeKey;
}
