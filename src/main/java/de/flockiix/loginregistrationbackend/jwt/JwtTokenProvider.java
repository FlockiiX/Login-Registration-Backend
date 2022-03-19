package de.flockiix.loginregistrationbackend.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.model.UserPrincipal;
import de.flockiix.loginregistrationbackend.config.properties.JwtProperties;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static de.flockiix.loginregistrationbackend.constant.JwtConstant.AUDIENCE;
import static de.flockiix.loginregistrationbackend.constant.JwtConstant.ISSUER;

@Component
public class JwtTokenProvider {
    private final JwtProperties jwtProperties;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }

    public String generateJwtAccessToken(User user) {
        String[] authorities = getAuthoritiesFromUser(new UserPrincipal(user));
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withIssuedAt(new Date())
                .withSubject(user.getEmail())
                .withArrayClaim("AUTHORITIES", authorities)
                .withClaim("userId", user.getUserId())
                .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(jwtProperties.getAccessTokenExpiresIn())))
                .sign(Algorithm.HMAC512(jwtProperties.getAccessTokenSecret().getBytes()));
    }

    private String[] getAuthoritiesFromUser(UserPrincipal userPrincipal) {
        List<String> authorities = new ArrayList<>();
        userPrincipal
                .getAuthorities()
                .forEach(grantedAuthority -> authorities.add(grantedAuthority.getAuthority()));
        return authorities.toArray(new String[0]);
    }

    public String generateJwtRefreshToken(User user) {
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
                .withIssuer(ISSUER)
                .withAudience(AUDIENCE)
                .withIssuedAt(new Date())
                .withSubject(user.getEmail())
                .withClaim("userId", user.getUserId())
                .withClaim("refreshTokenCount", user.getRefreshTokenCount())
                .withExpiresAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(jwtProperties.getRefreshTokenExpiresIn())))
                .sign(Algorithm.HMAC512(jwtProperties.getRefreshTokenSecret().getBytes()));
    }

    public List<GrantedAuthority> getAuthoritiesFromToken(String token) {
        String[] claims = getAuthorities(token);
        return Arrays.stream(claims)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private String[] getAuthorities(String token) {
        return verify(token, true)
                .getClaim("AUTHORITIES")
                .asArray(String.class);
    }

    public String getSubject(String token, boolean accessToken) {
        return verify(token, accessToken).getSubject();
    }

    public boolean isTokenValid(String email, String token, boolean accessToken) {
        Date expiration = verify(token, accessToken).getExpiresAt();
        return StringUtils.isNotEmpty(email) && !expiration.before(new Date());
    }

    public int getRefreshTokenCountFromToken(String token) {
        Claim count = verify(token, false).getClaim("refreshTokenCount");
        return count.asInt();
    }

    private DecodedJWT verify(String token, boolean accessToken) {
        JWTVerifier verifier = getJWTVerifier(accessToken);
        return verifier.verify(token);
    }

    private JWTVerifier getJWTVerifier(boolean accessToken) {
        String secret = accessToken ? jwtProperties.getAccessTokenSecret() : jwtProperties.getRefreshTokenSecret();
        JWTVerifier verifier;
        try {
            Algorithm algorithm = Algorithm.HMAC512(secret);
            verifier = JWT
                    .require(algorithm)
                    .withIssuer(ISSUER)
                    .build();
        } catch (JWTVerificationException exception) {
            throw new JWTVerificationException("Token cannot be verified");
        }

        return verifier;
    }
}

