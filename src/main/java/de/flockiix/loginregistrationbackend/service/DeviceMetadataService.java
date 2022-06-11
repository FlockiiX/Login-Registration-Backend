package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.User;

public interface DeviceMetadataService {
    void verifyDevice(User user, String ip, String userAgent);
}
