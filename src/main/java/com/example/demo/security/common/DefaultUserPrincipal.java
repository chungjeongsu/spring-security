package com.example.demo.security.common;

import com.example.demo.user.Role;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

import java.nio.file.attribute.UserPrincipal;

@Getter
@Builder
@AllArgsConstructor
public class DefaultUserPrincipal implements UserPrincipal {
    private Long id;
    private Role role;
    private String name;

    @Override
    public String getName() {
        return name;
    }

    //타입 파싱은 암묵적으로 각 필드와 동일하다고 가정한다.(타입 체크 생략. 후에 리팩토링 시 추가 예정)
    public static DefaultUserPrincipal from(Claims claims){
        return DefaultUserPrincipal.builder()
                .id((Long) claims.get("id"))
                .role(Role.valueOf((String) claims.get("role")))
                .name((String) claims.get("name"))
                .build();
    }
}
