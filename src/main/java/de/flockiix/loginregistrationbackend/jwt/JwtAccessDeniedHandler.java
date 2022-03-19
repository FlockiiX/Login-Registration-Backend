package de.flockiix.loginregistrationbackend.jwt;

import de.flockiix.loginregistrationbackend.model.HttpResponse;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
public class JwtAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException {
        HttpResponse httpResponse = Utils.buildHttpResponse(UNAUTHORIZED, "You do not have permission to access this page");
        Utils.handleResponse(httpResponse, response);
    }
}
