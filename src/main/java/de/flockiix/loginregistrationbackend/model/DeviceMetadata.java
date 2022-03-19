package de.flockiix.loginregistrationbackend.model;

import javax.persistence.*;
import java.util.Date;

@Entity
public class DeviceMetadata {
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "device_metadata_sequence"
    )
    @SequenceGenerator(
            name = "device_metadata_sequence",
            allocationSize = 1
    )
    private Long id;
    private Date lastLoggedIn;
    private String ip;
    private String deviceDetails;
    private String location;
    @ManyToOne(
            targetEntity = User.class,
            fetch = FetchType.EAGER
    )
    @JoinColumn(
            nullable = false,
            name = "user_id"
    )
    private User user;

    public DeviceMetadata(String ip, String deviceDetails, String location, User user) {
        this.lastLoggedIn = new Date();
        this.ip = ip;
        this.deviceDetails = deviceDetails;
        this.location = location;
        this.user = user;
    }

    public DeviceMetadata() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Date getLastLoggedIn() {
        return lastLoggedIn;
    }

    public void setLastLoggedIn(Date lastLoggedIn) {
        this.lastLoggedIn = lastLoggedIn;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getDeviceDetails() {
        return deviceDetails;
    }

    public void setDeviceDetails(String deviceDetails) {
        this.deviceDetails = deviceDetails;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
