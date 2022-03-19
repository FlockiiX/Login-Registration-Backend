package de.flockiix.loginregistrationbackend.util;

import org.apache.commons.io.IOUtils;

import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.stream.Collectors;

public class RequestWrapper extends HttpServletRequestWrapper {
    private byte[] bytes;

    public RequestWrapper(HttpServletRequest request) {
        super(request);
        try {
            InputStream inputStream = request.getInputStream();
            this.bytes = IOUtils.toByteArray(inputStream);
        } catch (IOException exception) {
            exception.printStackTrace();
        }
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(bytes);
        return new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return false;
            }

            @Override
            public boolean isReady() {
                return false;
            }

            @Override
            public void setReadListener(ReadListener listener) {

            }

            @Override
            public int read() throws IOException {
                return byteArrayInputStream.read();
            }
        };
    }

    @Override
    public BufferedReader getReader() throws IOException {
        return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
    }

    public String getBody() throws IOException {
        if (getReader().readLine() == null || Objects.equals(getReader().readLine(), ""))
            return "Empty Body";
        return getReader().lines().collect(Collectors.joining());
    }

    public String getParamsString() {
        StringBuilder params = new StringBuilder();
        getParameterMap().forEach((key, value) -> params.append(key).append("=").append(value[0]));
        if (params.length() == 0)
            return "Empty Parameters";
        return params.insert(0, "?").toString();
    }
}
