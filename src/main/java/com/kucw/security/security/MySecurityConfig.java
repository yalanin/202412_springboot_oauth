package com.kucw.security.security;

import com.kucw.security.dao.OAuth2MemberDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class MySecurityConfig {

    @Autowired
    private MyOAuth2UserService myOAuth2UserService;

    @Autowired
    private MyOidcUserService myOidcUserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http
                .authorizeHttpRequests(request -> request
                        .anyRequest().authenticated()
                )

                // 表單登入（即是使用帳號密碼登入）
                .formLogin(Customizer.withDefaults())

                // OAuth 2.0 社交登入
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(infoEndpoint -> infoEndpoint
                                .userService(myOAuth2UserService)
                                .oidcUserService(myOidcUserService)
                        )
                )

                .build();
    }
}
