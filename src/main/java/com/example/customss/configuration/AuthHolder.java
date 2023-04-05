package com.example.customss.configuration;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 인증 관련 정보를 넣어두는 Holder
 */
@Component
public class AuthHolder {

    private static boolean isLogined;
    private static @Getter @Setter String userName;
    private static @Getter @Setter String userEmail;
    private static @Getter @Setter List<String> authorities;

    public boolean Logined() {
        return this.isLogined;
    }

    public void isLogined(boolean s) {
        this.isLogined = s;
    }

}
