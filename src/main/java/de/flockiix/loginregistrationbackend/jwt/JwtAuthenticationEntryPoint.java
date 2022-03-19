package de.flockiix.loginregistrationbackend.jwt;

import de.flockiix.loginregistrationbackend.model.HttpResponse;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpStatus.FORBIDDEN;

@Component
public class JwtAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        HttpResponse httpResponse = Utils.buildHttpResponse(FORBIDDEN, "You need to log in to access this page");
        Utils.handleResponse(httpResponse, response);
    }
}
