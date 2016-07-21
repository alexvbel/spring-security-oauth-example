package com.abel.spring.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@EnableResourceServer
@SpringBootApplication
public class SpringSecurityOauthResourceServerApplication {


    @RequestMapping(path = "/userinfo")
    public String userinfo(Principal principal) {
        return new StringBuilder("Current user: ").append(principal.getName()).toString();
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityOauthResourceServerApplication.class, args);
    }
}
