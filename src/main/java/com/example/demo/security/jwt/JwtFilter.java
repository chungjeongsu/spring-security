package com.example.demo.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    @Value("${plus-uri.jwt-authentication-filter.oauth_success_login_code_start_with}")
    private String oauthSuccessLoginCodeStartWith;

    @Value("${plus-uri.jwt-authentication-filter.oauth_login_request_uri_start_with}")
    private String oauthLoginRequestUriStartWith;

    private final JwtUtil jwtUtil;

    /**
     * JWT 필터의 동작
     * 1. JWT를 검증한다.
     * 2. Bearer를 제외한 jwt(String)을 꺼내온다.
     * 3. SecurityContextHolder(ThreadLocal)에 UserDetail을 세팅
     * 4. 다음 필터로 넘긴다.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws AuthenticationException, ServletException, IOException {
        jwtUtil.validate(request.getHeader("Authorization"));
        String jwt = resolveToken(request);
        setSecurityContextHolder(jwt);
        filterChain.doFilter(request, response);
    }
    //request의 header에서 jwt를 빼온다.
    private String resolveToken(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        return authorization.replace("Bearer ", "").trim();
    }
    //securityContextHolder에 jwt를 저장한다.
    private void setSecurityContextHolder(String jwt) {
        Authentication authentication = jwtUtil.toAuthentication(jwt);
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
