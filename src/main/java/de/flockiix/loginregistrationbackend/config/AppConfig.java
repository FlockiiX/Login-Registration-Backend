package de.flockiix.loginregistrationbackend.config;

import com.maxmind.geoip2.DatabaseReader;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import ua_parser.Parser;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class AppConfig {
    @Value("classpath:maxmind/GeoLite2-City.mmdb")
    private Resource geoLiteCity;

    @Bean
    public Parser uaParser() {
        return new Parser();
    }

    @Bean(name = "GeoIPCity")
    public DatabaseReader databaseReader() throws IOException {
        return new DatabaseReader.Builder(geoLiteCity.getFile()).build();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.addAllowedHeader("*");
        config.addExposedHeader("Jwt-Token");
        config.addAllowedMethod("OPTIONS");
        config.addAllowedMethod("GET");
        config.addAllowedMethod("POST");
        config.addAllowedMethod("PUT");
        config.addAllowedMethod("DELETE");
        config.setAllowedOrigins(Collections.singletonList(""));
        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}
