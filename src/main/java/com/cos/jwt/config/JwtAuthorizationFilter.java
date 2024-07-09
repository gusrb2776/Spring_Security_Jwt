package com.cos.jwt.config;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

// 시큐리티가 filter를 가지고 있는데, 그 필터중에 BasciAuthenticationFilter 라는 것이 있음.
// 권한이나 인증이 필요한 특정 주소를 요청했을 때, 무조건 이 필터를 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 안탐.
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authManager, UserRepository userRepository) {
        super(authManager);
        this.userRepository = userRepository;
    }

    /**
     * 인증이나 권한이 필요한 주소요청이 있을 때, 해당 필터(BasicAuth...)를 타게 됨.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("인증이나 권한이 필요한 주소 요청됨.");

        // request의 헤더의 Authorization 확인
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader = " + jwtHeader);

        // Header가 있는지 체크
        if(jwtHeader == null || !jwtHeader.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }
        // JWT 토큰을 검증해서 정상적인 사용자인지 체크
        // 토큰만 빼내는거임.--> Bearer 하고 띄우는거 주의.
        String jwtToken = request.getHeader("Authorization").replace("Bearer ", "");

        // 서명(검증하기)
            // 서명하고 정상적이면 키가 username인 값을 들고와서 String으로 바꿔주는거임.
        String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwtToken).getClaim("username").asString();
        System.out.println("username = " + username);

        // 서명 정상적으로 됨.
        if (username != null) {
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // 원래는 로그인 진행을 해서 Authentication을 만들었는데, 지금은 서명을 위한거라 로그인없이 강제로 만들거야.
            // 강제로 만들어줄때, userDetail객체, password, 권한을 넣어주면 됨.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 시큐리티 세션에 접근하게 도와주는 Holder를 통해 Authentication 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        chain.doFilter(request, response);
    }
}
