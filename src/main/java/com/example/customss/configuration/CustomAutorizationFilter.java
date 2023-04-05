package com.example.customss.configuration;

import com.example.customss.service.AuthService;
import com.example.customss.utils.JwtUtils;
import io.jsonwebtoken.Claims;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.rmi.server.ExportException;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomAutorizationFilter extends OncePerRequestFilter {

    private final AuthService authService;
    private final JwtUtils jwtUtils;

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
            SecurityContext currentContext = SecurityContextHolder.getContext();
            log.info(currentContext.toString());

            if(currentContext.getAuthentication() == null)
            {
                log.info("최초 접속 로그인 수행: {}", targetUser.getSubject());

                UsernamePasswordAuthenticationToken internalToken   = new UsernamePasswordAuthenticationToken(targetUser.getId(), targetToken);
                Authentication currentUserAuthentication            = authService.setAuthentication(internalToken);

                SecurityContext newContext                          = SecurityContextHolder.createEmptyContext();

                newContext.setAuthentication(currentUserAuthentication);
                SecurityContextHolder.setContext(newContext);

                log.info("로그인 완료");

            }

            else
            {
                log.info("현재 접속자, 현재 context와 동일한지 검증 시행");
                throw new UserPrincipalNotFoundException("존재하지 않는 유저");
            }

        }

        else
        {

        }

        chain.doFilter(request, response);
    }
}
