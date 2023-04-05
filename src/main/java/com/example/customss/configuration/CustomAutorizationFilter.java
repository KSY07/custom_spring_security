package com.example.customss.configuration;

import com.example.customss.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.attribute.UserPrincipalNotFoundException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAutorizationFilter extends OncePerRequestFilter {

    private final JwtUtils jwtUtils;

    private final AuthHolder authHolder;

    /**\
     * JWT 토큰을 검사함
     * 1. 최초 로그인 이후 토큰, 유효 할 시 Security Context Holder 에 Security Context를 생성하여 보관
     * 2. 토큰 없을시, 자원 이용 차단.
     * 3. 이후, 토큰 Expired만 검사
     *
     * @author 김세영
     * @param req  The request to process
     * @param res The response associated with the request
     * @param chain    Provides access to the next filter in the chain for this
     *                 filter to pass the request and response to for further
     *                 processing
     *
     * @throws IOException
     * @throws ServletException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;

        String targetToken = request.getHeader("token");

        boolean isValid = jwtUtils.validateToken(targetToken);

        if(isValid)
        {
            Claims targetUser = jwtUtils.getJwtContents(targetToken);

            log.info(targetUser.toString());
            log.info(targetUser.getExpiration().toString());
            log.info(String.valueOf(targetUser.getExpiration().getTime()));
            log.info(targetUser.getSubject());

            String userName = targetUser.getSubject();



            if(!authHolder.Logined())
            {
                log.info("최초 접속 로그인 실행: {}", targetUser);
                authHolder.setUserName(userName);
                authHolder.isLogined(true);
                log.info("로그인 완료: {}", userName);
            }

            else
            {
                String currentUserName = authHolder.getUserName();
                log.info("로그인 되어있습니다. : {}", currentUserName);

            }

        }

        else
        {
            log.error("Token is Not Valid, Please ReLogin");
            // 리프레시 토큰 검증 및 인증 서버로 Redirect 로직 필요.(2023-04-05)
            throw new UserPrincipalNotFoundException("Permission Denied"); //예외를 던지며 요청 거부.
        }

        chain.doFilter(request, response);
    }
}
