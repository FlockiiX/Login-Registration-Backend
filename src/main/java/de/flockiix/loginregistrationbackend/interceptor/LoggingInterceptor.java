package de.flockiix.loginregistrationbackend.interceptor;

import de.flockiix.loginregistrationbackend.model.RequestLog;
import de.flockiix.loginregistrationbackend.repository.RequestLogRepository;
import de.flockiix.loginregistrationbackend.util.RequestWrapper;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

@Component
public class LoggingInterceptor implements HandlerInterceptor {
    private final RequestLogRepository requestLogRepository;

    public LoggingInterceptor(RequestLogRepository requestLogRepository) {
        this.requestLogRepository = requestLogRepository;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String requestId = UUID.randomUUID().toString();
        long requestTime = System.currentTimeMillis();
        request.setAttribute("requestId", requestId);
        request.setAttribute("requestTime", requestTime);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        long requestTime = (Long) request.getAttribute("requestTime");
        long executionMilliseconds = System.currentTimeMillis() - requestTime;
        RequestWrapper requestWrapper = new RequestWrapper(request);
        String body = requestWrapper.getBody();
        if (Arrays.stream(new String[]{"/login", "/register", "/updatePassword", "/resetPassword"}).anyMatch(request.getRequestURI()::contains)) {
            body = "hidden";
        }

        RequestLog requestLog = new RequestLog(
                request.getAttribute("requestId").toString(),
                new Date(),
                executionMilliseconds,
                Utils.getClientIpAddress(request),
                request.getMethod(),
                request.getRequestURI(),
                body,
                requestWrapper.getParamsString(),
                response.getStatus()
        );

        requestLogRepository.save(requestLog);
    }
}
