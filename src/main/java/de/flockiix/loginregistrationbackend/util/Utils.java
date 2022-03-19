package de.flockiix.loginregistrationbackend.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.flockiix.loginregistrationbackend.model.HttpResponse;
import org.springframework.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
import java.util.StringTokenizer;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

public class Utils {
    /**
     * Builds a custom http response.
     *
     * @param httpStatus the http status
     * @param message    the custom message
     * @return the http response
     */
    public static HttpResponse buildHttpResponse(HttpStatus httpStatus, String message) {
        return new HttpResponse(
                httpStatus.value(),
                httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(),
                message
        );
    }

    /**
     * Handles the response.
     *
     * @param httpResponse the http response
     * @param response     the http servlet response
     * @throws IOException when there is an error
     */
    public static void handleResponse(HttpResponse httpResponse, HttpServletResponse response) throws IOException {
        response.setContentType(APPLICATION_JSON_VALUE);
        response.setStatus(httpResponse.getHttpStatusCode());
        OutputStream outputStream = response.getOutputStream();
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(outputStream, httpResponse);
        outputStream.flush();
    }

    /**
     * Gets the client ip address out of a request.
     *
     * @param request the http servlet request
     * @return the client ip address
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        String xForwardedForHeader = request.getHeader("X-Forwarded-For");
        if (xForwardedForHeader == null)
            return request.getRemoteAddr();
        else
            return new StringTokenizer(xForwardedForHeader, ",").nextToken().trim();
    }

    /**
     * Checks if the string is a valid long.
     *
     * @param string the string you want to check
     * @return {@code true} if the string is a valid long and {@code false} otherwise
     */
    public static boolean isValidLong(String string) {
        try {
            Long.parseLong(string);
        } catch (NumberFormatException exception) {
            return false;
        }

        return true;
    }
}
