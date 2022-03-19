package de.flockiix.loginregistrationbackend.model;

import javax.persistence.*;
import java.util.Date;

@Entity
public class RequestLog {
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "request_log_sequence"
    )
    @SequenceGenerator(
            name = "request_log_sequence",
            allocationSize = 1
    )
    private Long id;
    private String requestId;
    private Date requestTime;
    private long executionMilliseconds;
    private String ip;
    private String method;
    private String url;
    private String body;
    private String parameters;
    private int statusCode;

    public RequestLog(String requestId, Date requestTime, long executionMilliseconds, String ip, String method, String url, String body, String parameters, int statusCode) {
        this.requestId = requestId;
        this.requestTime = requestTime;
        this.executionMilliseconds = executionMilliseconds;
        this.ip = ip;
        this.method = method;
        this.url = url;
        this.body = body;
        this.parameters = parameters;
        this.statusCode = statusCode;
    }

    public RequestLog() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public Date getRequestTime() {
        return requestTime;
    }

    public void setRequestTime(Date requestTime) {
        this.requestTime = requestTime;
    }

    public long getExecutionMilliseconds() {
        return executionMilliseconds;
    }

    public void setExecutionMilliseconds(long executionMilliseconds) {
        this.executionMilliseconds = executionMilliseconds;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }

    public String getParameters() {
        return parameters;
    }

    public void setParameters(String parameters) {
        this.parameters = parameters;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }
}
