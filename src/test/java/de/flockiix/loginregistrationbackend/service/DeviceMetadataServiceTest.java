package de.flockiix.loginregistrationbackend.service;

import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import de.flockiix.loginregistrationbackend.model.DeviceMetadata;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.DeviceMetadataRepository;
import de.flockiix.loginregistrationbackend.service.impl.DeviceMetadataServiceImpl;
import de.flockiix.loginregistrationbackend.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import ua_parser.Parser;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class DeviceMetadataServiceTest {

    private DeviceMetadataService deviceMetadataService;
    @Mock
    private Parser parser;
    @Mock
    private DatabaseReader databaseReader;
    @Mock
    private DeviceMetadataRepository deviceMetadataRepository;
    @Mock
    private EmailService emailService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        deviceMetadataService = new DeviceMetadataServiceImpl(parser, databaseReader, deviceMetadataRepository, emailService);
    }

    @Test
    void verifyDevice() throws IOException, GeoIp2Exception {
        User user = TestUtils.getUser();
        String ip = "123";
        String userAgent = "None";
        given(databaseReader.city(InetAddress.getByName(ip))).willReturn(null);
        given(parser.parse(userAgent)).willReturn(null);
        given(deviceMetadataRepository.findDeviceMetadataByUser(user)).willReturn(Collections.emptyList());
        deviceMetadataService.verifyDevice(user, ip, userAgent);
        ArgumentCaptor<DeviceMetadata> argumentCaptor = ArgumentCaptor.forClass(DeviceMetadata.class);
        verify(deviceMetadataRepository).save(argumentCaptor.capture());
        DeviceMetadata capturedData = argumentCaptor.getValue();
        assertThat(capturedData.getDeviceDetails()).isEqualTo("UNKNOWN");
        assertThat(capturedData.getLocation()).isEqualTo("UNKNOWN");
        assertThat(capturedData.getIp()).isEqualTo(ip);
        assertThat(capturedData.getUser()).isEqualTo(user);
    }
}