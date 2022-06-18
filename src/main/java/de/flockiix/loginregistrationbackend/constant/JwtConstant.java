package de.flockiix.loginregistrationbackend.constant;

public class JwtConstant {
    public static final String ISSUER = "FlockiiX";
    public static final String AUDIENCE = "FlockiiX User Management";
    public static final String[] PUBLIC_URLS = {"/api/**/auth/login", "/api/**/auth/refresh", "/api/**/user/register", "/api/**/user/confirm", "/api/**/user/resetPassword"};
}
