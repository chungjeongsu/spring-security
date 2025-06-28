package com.example.demo.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum Role {
    USER("기본적인 유저의 권한"),
    ADMIN("관리자 권한");

    private final String role;
}
