package de.flockiix.loginregistrationbackend.service.impl;

import com.google.common.base.Strings;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CityResponse;
import de.flockiix.loginregistrationbackend.constant.EmailConstant;
import de.flockiix.loginregistrationbackend.exception.DeviceVerificationException;
import de.flockiix.loginregistrationbackend.model.DeviceMetadata;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.DeviceMetadataRepository;
import de.flockiix.loginregistrationbackend.service.DeviceMetadataService;
import de.flockiix.loginregistrationbackend.service.EmailService;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import ua_parser.Client;
import ua_parser.Parser;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;
import java.util.List;

@Service
public class DeviceMetadataServiceImpl implements DeviceMetadataService {
    private final Parser parser;
    private final DatabaseReader databaseReader;
    private final DeviceMetadataRepository deviceMetadataRepository;
    private final EmailService emailService;

    @Autowired
    public DeviceMetadataServiceImpl(Parser parser, @Qualifier("GeoIPCity") DatabaseReader databaseReader, DeviceMetadataRepository deviceMetadataRepository, EmailService emailService) {
        this.parser = parser;
        this.databaseReader = databaseReader;
        this.deviceMetadataRepository = deviceMetadataRepository;
        this.emailService = emailService;
    }

    @Override
    public void verifyDevice(User user, HttpServletRequest request) {
        try {
            var ip = Utils.getClientIpAddress(request);
            var location = getIpLocation(ip);
            var deviceDetails = getDeviceDetails(request.getHeader("User-Agent"));
            var existingDevice = findExistingDevice(user, deviceDetails, location);
            var devices = findExistingDevices(user);

            if (existingDevice != null) {
                existingDevice.setLastLoggedIn(new Date());
                return;
            }

            if (devices != 0)
                emailService.sendEmail(user.getEmail(), "New device", EmailConstant.buildSafetyWarningEmail(user.getFirstName()));

            DeviceMetadata metadata = new DeviceMetadata(
                    ip,
                    deviceDetails,
                    location,
                    user
            );

            deviceMetadataRepository.save(metadata);
        } catch (Exception exception) {

            throw new DeviceVerificationException("Failed to verify Device");
        }
    }

    private String getDeviceDetails(String userAgent) {
        String deviceDetails = "UNKNOWN";
        Client client = parser.parse(userAgent);
        if (client != null)
            deviceDetails = client.userAgent.family + " " + client.userAgent.major + "." + client.userAgent.minor + " - " + client.os.family + " " + client.os.major + "." + client.os.minor;

        return deviceDetails;
    }

    private String getIpLocation(String ip) throws IOException, GeoIp2Exception {
        String location = "UNKNOWN";
        InetAddress ipAddress = InetAddress.getByName(ip);
        CityResponse cityResponse = databaseReader.city(ipAddress);
        if (cityResponse != null && cityResponse.getCity() != null && !Strings.isNullOrEmpty(cityResponse.getCity().getName()))
            location = cityResponse.getCity().getName();

        return location;
    }

    private DeviceMetadata findExistingDevice(User user, String deviceDetails, String location) {
        List<DeviceMetadata> knownDevices = deviceMetadataRepository.findDeviceMetadataByUser(user);
        for (DeviceMetadata existingDevice : knownDevices)
            if (existingDevice.getDeviceDetails().equals(deviceDetails) && existingDevice.getLocation().equals(location))
                return existingDevice;

        return null;
    }

    private int findExistingDevices(User user) {
        return deviceMetadataRepository.findDeviceMetadataByUser(user).size();
    }
}
