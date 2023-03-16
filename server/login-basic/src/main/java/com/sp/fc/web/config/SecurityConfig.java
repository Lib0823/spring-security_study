package com.sp.fc.web.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;


@EnableWebSecurity(debug = true)
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    // 로그인시 csrf토근이 제대로 발급되지 않을 시
    // loginForm의 form action을 타임리프 속성으로 지정한다. th:action="@{/login}"

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser(
                        User.withDefaultPasswordEncoder()
                                .username("user1")
                                .password("1111")
                                .roles("USER")      // Controller에서 지정한 role만 접근할 수 있음.
                                                    // @PreAuthorize("hasAnyAuthority('ROLE_USER')")
                ).withUser(
                        User.withDefaultPasswordEncoder()
                                .username("admin")
                                .password("2222")
                                .roles("ADMIN")
                );

    }

    @Bean
    RoleHierarchy roleHierarchy(){  // admin은 user보다 높기때문에 user도 접근 가능하게 설정
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_USER");
        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(request->{
                    request
                            .antMatchers("/").permitAll()   // root페이지는 접근 허용
                            .anyRequest().authenticated()              // 다른 페이지는 권한 필요
                            ;
                })
                .formLogin( // 로그인시
                        login->login.loginPage("/login") // 로그인페이지 지정
                                .permitAll()
                                .defaultSuccessUrl("/", false)  // 로그인시 디폴트는 root이고, alwaysUse를 false로 지정해 원래 있더 페이지로 보낸다.
                                .failureUrl("/login-error")
                )
                .logout(logout->logout.logoutSuccessUrl("/")) // 로그아웃시 root페이지 이동
                .exceptionHandling(exception->exception.accessDeniedPage("/access-denied")) // 접근 권한이 없을 때 페이지 지정
                ;
    }

    // Web Resource에 대해서는 Spring Security를 타지 않게 한다.
    // resources > static 폴더에 있는 파일만 적용됨
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring()
                .requestMatchers(
                        PathRequest.toStaticResources().atCommonLocations()
                );
    }
}
