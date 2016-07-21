package com.abel.spring.security.oauth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.sql.ResultSet;

/**
 * Password
 * curl -s acme:acmesecret@localhost:9999/uaa/oauth/token   -d grant_type=password  -d client_id=acme  -d scope=webshop  -d username=user  -d password=secret
 * <p>
 * Client credentials
 * curl -s acme:acmesecret@localhost:9999/uaa/oauth/token   -d grant_type=client_credentials  -d scope=webshop
 * <p>
 * <p>
 * Authorization code
 * http://localhost:9999/uaa/oauth/authorize?response_type=code&client_id=acme&redirect_uri=http://example.com&scope=webshop&state=48532
 * http://localhost:9999/uaa/oauth/authorize?response_type=authorization_code&client_id=acme&redirect_uri=http://example.com&code=$CODE
 * <p>
 * Implicit:
 * http://localhost:9999/uaa/oauth/authorize?response_type=token&client_id=acme&redirect_uri=http://example.com&scope=webshop&state=48532
 */
@EnableResourceServer
@SpringBootApplication
@RestController
public class SpringSecurityOauthServerApplication {

    @RequestMapping("/user")
    public Principal user(Principal principal) {
        return principal;
    }

    @Bean
    public UserDetailsService userDetailsService(JdbcTemplate jdbcTemplate) {
        RowMapper<User> userRowMapper = (ResultSet rs, int i) ->
                new User(rs.getString("ACCOUNT_NAME"), rs.getString("PASSWORD"),
                        rs.getBoolean("ENABLED"),
                        rs.getBoolean("ENABLED"),
                        rs.getBoolean("ENABLED"),
                        rs.getBoolean("ENABLED"),
                        AuthorityUtils.createAuthorityList("ROLE_USER", "ROLE_ADMIN")
                );
        return username -> jdbcTemplate.queryForObject("select * from account where account_name = ?", userRowMapper, username);
    }

    @Configuration
    @EnableAuthorizationServer
    public static class OAuthConfiguration extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager authenticationManager;

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints.authenticationManager(authenticationManager);
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("acme")
                    .secret("acmesecret")
                    .authorizedGrantTypes("authorization_code", "refresh_token", "implicit", "password", "client_credentials")
                    .scopes("webshop");
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityOauthServerApplication.class, args);
    }
}
