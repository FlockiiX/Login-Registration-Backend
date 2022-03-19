package de.flockiix.loginregistrationbackend.filter;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import de.flockiix.loginregistrationbackend.model.HttpResponse;
import de.flockiix.loginregistrationbackend.config.properties.SecurityProperties;
import de.flockiix.loginregistrationbackend.util.RequestWrapper;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.springframework.http.HttpStatus.TOO_MANY_REQUESTS;

@Component
public class RequestThrottleFilter implements Filter {
    private static final Logger LOGGER = LoggerFactory.getLogger(RequestThrottleFilter.class);
    private final SecurityProperties securityProperties;
    private final LoadingCache<String, Integer> requestsPerIpAddress;

    public RequestThrottleFilter(SecurityProperties securityProperties) {
        super();
        this.securityProperties = securityProperties;
        requestsPerIpAddress = CacheBuilder.newBuilder()
                .expireAfterWrite(3, TimeUnit.SECONDS)
                .build(new CacheLoader<>() {
                    @Override
                    public Integer load(String key) {
                        return 0;
                    }
                });
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) servletRequest;
        HttpServletResponse httpServletResponse = (HttpServletResponse) servletResponse;
        String clientIpAddress = Utils.getClientIpAddress(httpServletRequest);
        if (isMaximumRequestsPerSecondExceeded(clientIpAddress)) {
            HttpResponse httpResponse = Utils.buildHttpResponse(TOO_MANY_REQUESTS, "Too many requests");
            Utils.handleResponse(httpResponse, httpServletResponse);
            return;
        }

        RequestWrapper requestWrapper = new RequestWrapper(httpServletRequest);
        filterChain.doFilter(requestWrapper, servletResponse);
    }

    /**
     * Checks if the maximum of requests per second is exceeded.
     *
     * @param clientIpAddress the client ip address
     * @return true if the maximum of requests per second is exceeded and false otherwise
     */
    private boolean isMaximumRequestsPerSecondExceeded(String clientIpAddress) {
        int requests = getRequestsFromIp(clientIpAddress);
        if (requests > securityProperties.getRequestLimit()) {
            return true;
        }

        requestsPerIpAddress.put(clientIpAddress, ++requests);
        return false;
    }

    private int getRequestsFromIp(String clientIpAddress) {
        try {
            return requestsPerIpAddress.get(clientIpAddress);
        } catch (ExecutionException exception) {
            LOGGER.error("Cache loading failed", exception);
            return 0;
        }
    }
}
