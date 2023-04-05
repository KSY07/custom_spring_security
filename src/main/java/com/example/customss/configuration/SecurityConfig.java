package com.example.customss.configuration;

import com.example.customss.utils.JwtUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfiguration;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomAutorizationFilter customAutorizationFilter;

    @Bean
    public AuthenticationManager authenticationManagerBean(AuthenticationConfiguration authConfig) throws Exception{
        return authConfig.getAuthenticationManager();
    }


    @Bean
    public SecurityFilterChain webConfig(HttpSecurity http) throws Exception {

        http.authorizeRequests(
                (authorize) -> {
                    authorize.anyRequest().authenticated();
                }
        ).addFilterBefore(customAutorizationFilter, BasicAuthenticationFilter.class); //Basic Authentication Filter가 실행전에 커스텀 필터 먼저 실행.

        return http.build();
    }


}
