package com.spring.config;

import com.spring.filter.AuthenticationProcessingFilter;
import com.spring.filter.JWTOncePerRequestFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Autowired
    @Qualifier("authenticationTokenFilter")
    private AuthenticationProcessingFilter filter;

    @Autowired
    private JWTOncePerRequestFilter oncePerRequestFilter;

    @Bean
    public FilterRegistrationBean<AuthenticationProcessingFilter> authenticationProcessingFilter() {
        FilterRegistrationBean<AuthenticationProcessingFilter> registrationBean = new FilterRegistrationBean();

        registrationBean.setFilter(filter);
        registrationBean.addUrlPatterns("/authenticate");
        return registrationBean;
    }


    @Bean
    public FilterRegistrationBean<JWTOncePerRequestFilter> jwtOncePerRequestFilter() {
        FilterRegistrationBean<JWTOncePerRequestFilter> registrationBean = new FilterRegistrationBean();

        registrationBean.setFilter(oncePerRequestFilter);
        registrationBean.addUrlPatterns("/api/*");
        return registrationBean;
    }


}