package com.example.demo.security.jwt;

import com.example.demo.security.common.DefaultUserPrincipal;
import com.example.demo.security.common.PrincipalKey;
import com.example.demo.user.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

/**
 * JWT 토큰만을 다루는 클래스이다.
 * JWT 생성, claims getter 등 JWT에 대한 메서드들이 있다.
 * JWT는 Bearer를 빼준 순수 String 토큰만 다룬다.
 * 런타임 시점 모든 필드들이 초기화 즉, 싱글톤 관리 @Component
 */

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-validity-ms}")
    private long jwtTokenValidityMs;
    private SecretKey key;

    @PostConstruct
    public void init(){
        byte[] keyBytes = Base64.getDecoder().decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * JWT 토큰을 생성한다.
     * 1.
     */
    public String generateJwtToken(Long userId, String name, Role role) {    //토큰 생성
        Date now = new Date();
        Date exp = new Date(now.getTime() + jwtTokenValidityMs);    //현재시간 + 유효시간 = 만료되는 시간

        return Jwts.builder()
                .claim(PrincipalKey.USER_ID.getKey(), userId)
                .claim(PrincipalKey.USER_NAME.getKey(), name)
                .claim(PrincipalKey.USER_ROLE.getKey(), role)
                .expiration(exp)
                .signWith(this.key)
                .compact();
    }

    /**
     * jwt 토큰에서 user의 principal을 추출해, Authentication으로 반환한다.
     * => Authentication(usernamePasswordAuthentication)은 SecurityContextHolder에 저장된다.
     * => SecurityContextHolder는 ThreadLocal이기 때문에, 생명주기가 하나의 요청이 된다.
     * => 즉, SecurityContextHolder에서 세팅 후, @AuthenticationPrincipal 로 꺼내올 수 있게 되는 것이다.
     * => Authentication(UsernamePasswordAuthentication)은 principal, null, List<GrantedAuthority>를 갖는다.
     * 1.claims를 jwt에서 파싱해온다.
     * 2.Principal을 준비한다.
     * 3.GrantedAuthority를 준비한다.
     * 4.이를 반환한다.
     */
    public Authentication toAuthentication(String jwt) {
        Claims claims = getClaims(jwt);
        DefaultUserPrincipal principal = DefaultUserPrincipal.from(claims);
        GrantedAuthority grantedAuthority = new SimpleGrantedAuthority((String) claims.get("role"));

        return new UsernamePasswordAuthenticationToken(
                principal,
                null,
                List.of(grantedAuthority)
        );
    }

    /**
     * jwt 토큰을 검사한다.
     * 1.Authorization 헤더에 값이 있는지 검증
     * 2.Authorization 헤더에 "Bearer "가 붙어있는지 검증
     * 3.jwt를 헤더에서 추출(Bearer를 뺀 순수 jwt)
     * 4.토큰 만료와, 유효성 검사(with key)
     */
    public void validate(String authorization) throws AuthenticationException {
        validateNotNullAuthorization(authorization);        // 1
        validateBearer(authorization);                      // 2
        String jwt = extractJwt(authorization);             // 3
        validateJwt(jwt);                                   // 4
    }

    // 1.Authorization 헤더에 값이 있는지 검증
    private void validateNotNullAuthorization(String authorization) throws AuthenticationException {
        if(authorization == null){
            throw new AuthenticationCredentialsNotFoundException("헤더에 Authorization이 없습니다.");
        }
    }

    // 2.Authorization 헤더에 "Bearer "가 붙어있는지 검증
    private void validateBearer(String jwt) {
        if(jwt.startsWith("Bearer ")){
            throw new AuthenticationCredentialsNotFoundException("Authorization 헤더 값은 Bearer 를 포함해야 합니다.");
        }
    }

    // 3.jwt를 헤더에서 추출(Bearer를 뺀 순수 jwt)
    private String extractJwt(String authorization) {
        return authorization.replace("Bearer ", "").trim();
    }

    // 4.토큰 만료와, 유효성 검사(with key)
    private void validateJwt(String jwt) {
        try{
            Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();
        }catch (ExpiredJwtException e){
            throw new AuthenticationServiceException("JWT 토큰이 만료되었습니다.");
        }catch (JwtException e){
            throw new AuthenticationServiceException("JWT 토큰 형식이 이상합니다.");
        }
    }

    /*
     * JwtUtil에서 핵심이 되는 메서드
     * 1.암호화된, jwt의 내용을 Claims라는 객체로 파싱한다.
     * 2.Jwt에는 개발자가 직접 값을 key:value로 세팅할 수 있다.
     * 3.getClaims.get("{세팅 key}")으로 JWT에 세팅해둔 값을 가져올 수 있다.
     */
    private Claims getClaims(String jwt) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jwt)
                .getPayload();
    }
}