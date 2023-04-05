package com.example.customss.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class JwtUtils {

    @Value("${auth.secretKey}")
    private String secretKey;

    public JwtUtils() {

    }

    /**
     * 토큰 검증
     * @param jwt
     * @return 유효하면 True, 유효하지 않으면 False
     */
    public boolean validateToken(String jwt) {
        try {
            Claims claims = Jwts.parser().setSigningKey(secretKey)
                    .parseClaimsJws(jwt).getBody();
            return true;
        } catch(ExpiredJwtException e) {
            log.error("Token Expired: {}", e);
            return false;
        } catch (JwtException e) {
            log.error("Token Exception: {}", e);
            return false;
        }
    }

    /**
     * Jwt 내부의 정보를 리턴
     * @param jwt
     * @return Claims (JWT 내부에 담긴 정보)
     */
    public Claims getJwtContents(String jwt) {
        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(jwt).getBody();

        return claims;
    }

}
