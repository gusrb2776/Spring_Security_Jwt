package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter가 있음.
// 원래 이 필터는 /login 요청을 해서 username과 password를 post로 요청하면 동작함.
// 근데 지금 우리가 formLogin(form -> form.disable())을 해버려서 이 필터가 작동을 안해.
// 이 필터를 다시 작동시킬려면 SecurityConfig에 다시 등록을 해주면 됨.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // AuthenticationManager는 이제 UsernamePasswordAuthenticationFilter를 등록할 때 필요한 파라미터임.
    private final AuthenticationManager authenticationManager;

    /**
     * 로그인 시도를 하기 위해서 실행되는 함수임.
     * 얘는 `/login` 요청을 하면 로그인 시도를 위해서 실행되는 함수임.
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter :  로그인 시도중");

        // 1. username, password 를 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            // 토큰을 만들자. 원래는 자동으로 해줌.
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // 이때 authenticationManager가 필요함. 얘한테 token을 날리면 PrincipalDetailsService의 loadUserByUsername()함수가 실행됨.
            // 이제 이 authentication에 내 로그인 정보가 담김.
            // 이게 있따는건 DB에 잇는 username과 password가 일치한다는건 알겠지?
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // authentication안에 principal이라는 객체를 가져옴.
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            // 출력이 된다 == 로그인 성공
            System.out.println(principalDetails.getUser().getUsername());

            // authentication 객체가 session영역에 저장을 해야하고 그방법이 return 해주면 되는거임.
            // 리턴의 이유는 권한 관리를 security가 대신 해주기 때문에 편하려고 하는거임
            // 굳이 JSWT 토큰을 사용하면서 세션을 만들 이유가 없는데, 권한처리가 편하자고 세션에 넣어주는거임.
            return authentication;
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println("-=====================꾸에엥================-");

        return null;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication이 실행 됨 : 인증이 완료되었다는 소리");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // 위의 데이터를 이용해서 jwt 라이브러리를 통해서 jwt토큰을 만들거야
        // RSA방식은 아니고 Hash암호화 방식임
        String jwtToken = JWT.create()
                // 토큰 이름 정하기
                .withSubject("cos토큰")
                // 만료시간 : 현재시간 + 만료시간 적는방식 10000 = 1분
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                // 여기는 내가 넣고싶은 key value값 마음대로 넣으면 됨.
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                // 서버만 알고있는 키 ( 이런식으로 적용하면 깔끔 해 )
                .sign(Algorithm.HMAC512(JwtProperties.SECRET));

        // 무조건 한칸 띄어서 적어야햄찌
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.HEADER_STRING + jwtToken);
    }
}
