package com.ureca.juksoon.global.security.oauth.userdetail;

import com.ureca.juksoon.domain.user.entity.UserRole;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * CustomOAuth2UserService에서 사용할 객체이다.
 * 모든 OAuth 사용자 인증은 Scope파라미터가 달라 하나로 파싱해주고 사용할 것이다.
 */
public class CustomOAuth2User implements OAuth2User {
    private final Map<String, Object> principals;

    public CustomOAuth2User(Map<String, Object> attributes) {
        this.principals = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return principals;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(principals.get(PrincipalKey.USER_ROLE.getKey()).toString()));
        return authorities;
    }

    @Override
    public String getName() {
        return "name";
    }

    public Long getUserId(){
        return (Long) principals.get(PrincipalKey.USER_ID.getKey());
    }

    public UserRole getUserRole(){ //사실상 role은 하나이기 때문에 만들어줌
        return UserRole.valueOf((String) principals.get(PrincipalKey.USER_ROLE.getKey()));
    }
}
