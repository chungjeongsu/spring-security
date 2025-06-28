package com.example.demo.security.oauth;

import com.ureca.juksoon.global.refresh.service.RefreshTokenService;
import com.ureca.juksoon.global.response.CustomCookieType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import java.io.IOException;

/**
 * 로그아웃 필터
 * LogoutFilter.class 가 동작하기 전에 동작하는 CustomLogoutFilter
 * 1. POST, /logout 요청으로 들어왔는지 uri 검사
 * 2. refresh 토큰이 이미 null 인 경우 비정상적인 접근이라고 판단하여 BAD_REQUEST
 * 3. refresh 토큰이 DB 에서 검색이 안될 경우 동일하게 BAD_REQUEST
 * 4. DB에서 토큰 삭제 및 SecurityContextHolder 클리어
 * 5. 카카오 계정과 함께 로그아웃 또는 서비스만 로그아웃 하는 리다이렉트 주소 지정
 */
@RequiredArgsConstructor
public class CustomLogoutFilter extends GenericFilterBean {

    private final RefreshTokenService refreshTokenService;
    @Value("${logout-with.kakao.logout-uri}")
    private String logoutUri;

    @Value("${spring.security.oauth2.client.registration.kakao.client-id}")
    private String clientId;

    @Value("${logout-with.kakao.logout-redirect-uri}")
    private String logoutRedirectUri;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {

        if (isInvalidRequest(request)) {

            filterChain.doFilter(request, response);
            return;
        }

        String refreshToken = getRefreshToken(request);

        if (isInvalidRefreshToken(refreshToken)){
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        doLogout(refreshToken, response);
    }

    /**
     * 쿠키에서 Refresh_Token 으로된 Key값을 꺼냄
     */
    private String getRefreshToken(HttpServletRequest request) {

        String refreshToken = null;

        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(CustomCookieType.REFRESH_TOKEN.getValue())) {
                refreshToken = cookie.getValue();
            }
        }

        return refreshToken;
    }

    /**
     * 검증 완료된 RefreshToken을 삭제
     * SecurityContextHolder 비우기
     * 카카오와 함께 로그아웃 리다이렉트
     */
    private void doLogout(String refreshToken, HttpServletResponse response) throws IOException {
        refreshTokenService.deleteByToken(refreshToken);

        Cookie cookie = new Cookie(CustomCookieType.AUTHORIZATION.getValue(), null);
        cookie.setMaxAge(0);
        cookie.setPath("/");

        SecurityContextHolder.clearContext();

        String url = logoutUri + "?client_id=" + clientId + "&logout_redirect_uri=" + logoutRedirectUri;
        response.setStatus(HttpServletResponse.SC_OK);
        response.addCookie(cookie);
        response.sendRedirect(url);
    }

    /**
     * 요청 uri 검사
     * /logout && POST
     */
    private boolean isInvalidRequest(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String requestMethod = request.getMethod();

        return !requestUri.matches("^\\/logout$") || !requestMethod.equals("POST");
    }

    private boolean isInvalidRefreshToken(String refreshToken){

        return refreshToken==null || !refreshTokenService.existsByToken(refreshToken);

    }
}