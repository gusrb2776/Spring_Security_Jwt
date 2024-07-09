package com.cos.jwt.controller;

import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestApiController {

    private final UserRepository userRepository;

    @Autowired
    private  BCryptPasswordEncoder bCryptPasswordEncoder;

    public RestApiController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("home")
    public String home(){
        return "홈화면";
    }

    @PostMapping("token")
    public String token(){
        return "<h1>token</h1>";
    }

    //
    @PostMapping("join")
    public String join(@RequestBody User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);

        return "회원가입 완료";
    }

    // user, manager, admin 모두 접근 가능
    @GetMapping("/api/v1/user")
    public String user(Authentication authentication){
        System.out.println("안녕하세요.");
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principal.getUsername() = " + principal.getUsername());
        return "user";
    }

    // manager, admin 접근 가능
    @GetMapping("/api/v1/manager")
    public String manager(){
        return "manager";
    }

    //admin 접근가능
    @GetMapping("/api/v1/admin")
    public String admin(){
        return "admin";
    }

}
