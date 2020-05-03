package com.spring.config;

import com.spring.filter.AuthenticationProcessingFilter;
import com.spring.handler.CustomAccessDeniedHandler;
import com.spring.handler.CustomAuthenticationFailureHandler;
import com.spring.handler.CustomAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
       // UserDetailsManagerConfigurer.UserDetailsBuilder builder = null;

                auth.inMemoryAuthentication()
                        .passwordEncoder(passwordEncoder())

                        .withUser("hari").password(passwordEncoder().encode("hari")).roles("user")
                        .and()
                        .withUser("ram").password(passwordEncoder().encode("ram")).roles("admin")
                        .and()
                        .withUser("xyz").password(passwordEncoder().encode("xyz")).roles("anyone");


    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic().disable();
        http.authorizeRequests()
                //antMatchers("/admin").hasRole("admin")
                //.antMatchers("/user").hasAnyRole("admin","user")
                .antMatchers("/authenticate","/","/accessDenied","/loginFailed").permitAll().anyRequest().authenticated()
                .and().formLogin().disable().

               // defaultSuccessUrl("/", true).
                exceptionHandling().
                accessDeniedHandler(accessDeniedHandler());

        http.csrf().disable();
        http.addFilterBefore(authenticationTokenFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean(name = "authenticationTokenFilter")
    public AuthenticationProcessingFilter authenticationTokenFilter()throws  Exception {
        AuthenticationProcessingFilter filter = new AuthenticationProcessingFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/authenticate", "POST"));
        filter.setAuthenticationSuccessHandler(new CustomAuthenticationSuccessHandler());
        filter.setAuthenticationFailureHandler(new CustomAuthenticationFailureHandler());
        return filter;
    }
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return new CustomAccessDeniedHandler();
    }
}
