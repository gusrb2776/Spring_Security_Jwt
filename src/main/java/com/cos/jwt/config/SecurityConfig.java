package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Configurable;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final CorsFilter corsFilter;

    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationConfiguration authenticationConfiguration) throws Exception {

        AuthenticationManager authenticationManager = authenticationConfiguration.getAuthenticationManager();

        http
                .csrf(csrf -> csrf.disable())
                // 세션 안쓸거야.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // JWT 서버라서 우리가 ID Password를 폼 로그인으로 안해.
                .formLogin(form -> form.disable())
                // 기본적인 HTTP 로그인 방식을 아예 안써 (여기까진 보통 고정임)
                .httpBasic(httpBasic -> httpBasic.disable())
                // 권한에 따른 접속 설정
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/api/v1/user/**").hasAnyRole("ADMIN", "MANAGER", "USER")
                        .requestMatchers("api/v1/manager/**").hasAnyRole("ADMIN", "MANAGER")
                        .requestMatchers("api/v1/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll())
                // cors정책 추가. @CrossOrigin은 인증이 필요 없을때사용. 인증 필요시 필터를 등록해줘야함.
                .addFilter(corsFilter)
//                .addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class)
                // `/login` 처리를 위한 필터 추가
                // 근데 이제 꼭 달아줘야하는 파라미터가 있어. AuthenticationManager라고 있음.
                .addFilter(new JwtAuthenticationFilter(authenticationManager))
                // 권한처리를 위한 필터 추가
                .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository));

        return http.build();
    }
}
