package com.example.demo.security.common;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum PrincipalKey {
    USER_ID("id"),
    USER_ROLE("role"),
    USER_NAME("name")
    ;

    private final String key;
}
