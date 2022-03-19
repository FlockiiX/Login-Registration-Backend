package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.User;

import javax.servlet.http.HttpServletRequest;

public interface DeviceMetadataService {
    void verifyDevice(User user, HttpServletRequest request);
}
