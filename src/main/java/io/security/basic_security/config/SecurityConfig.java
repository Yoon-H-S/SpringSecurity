package io.security.basic_security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserDetailsService userDetailsService;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception { // 사용자를 생성하기 위해 Override
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER"); // password에 {}는 패스워드를 암호화하는 방식을 지정해주는 것이다.
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN","SYS","USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 인가 API
        http
                .authorizeRequests()
//                .antMatchers("/login").permitAll()
//                .antMatchers("/user").hasRole("USER")
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        // 인증, 인가 API(Exception)
//        http
//                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        System.out.println("인증 예외 발생");
//                        response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        System.out.println("인가 예외 발생");
//                        response.sendRedirect("/denied");
//                    }
//                });

        http
                .formLogin();
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        // 인증 실패 시 캐시에 저장되었던 정보를 이용해 로그인을 성공하면 원하는 페이지로 이동
//                        RequestCache requestCache = new HttpSessionRequestCache();
//                        System.out.println("requestCache = " + requestCache);
//                        SavedRequest savedRequest = requestCache.getRequest(request, response);
//                        System.out.println("savedRequest = " + savedRequest);
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        System.out.println("redirectUrl = " + redirectUrl);
//                        response.sendRedirect(redirectUrl);
//                    }
//                });


        // 인증 API
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated(); // 어떤 요청을 받더라도 인증을 받아야 한다.라는 설정이다.

//        http
//                .formLogin();
//                .loginPage("/loginPage") // 이 경로는 인증을 받지 않아도 접근이 가능해야 한다.
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication = " + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception = " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll(); // 이 경로로 접근하는 사용자는 인증을 받지 않아도 된다.
//
//        http
//                .logout() // 기본적으로 POST방식
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        System.out.println("로그아웃을 위해 세션을 무효화합니다.");
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("로그아웃 성공");
//                        response.sendRedirect("/login");
//                    }
//                });
////                .deleteCookies("remember-me");
//        http
//                .rememberMe()
//                .rememberMeParameter("remember") // default : remember-me
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
//        http
//                .sessionManagement()
//                .maximumSessions(1)
////                .maxSessionsPreventsLogin(true); // 동시 로그인을 차단
//                .maxSessionsPreventsLogin(false);
//        http
//                .sessionManagement()
//                .sessionFixation().changeSessionId();
    }
}
