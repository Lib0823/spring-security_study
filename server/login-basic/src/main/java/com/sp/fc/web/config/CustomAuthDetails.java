package com.sp.fc.web.config;

import org.springframework.security.authentication.AuthenticationDetailsSource;

import javax.servlet.http.HttpServletRequest;

public class CustomAuthDetails implements AuthenticationDetailsSource<HttpServletRequest, RequestInfo> {
    @Override
    public RequestInfo buildDetails(HttpServletRequest request) {
        return null;
    }
}
