package de.flockiix.loginregistrationbackend.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.validation.annotation.ValidEmail;
import de.flockiix.loginregistrationbackend.validation.annotation.ValidPassword;
import org.apache.commons.lang3.RandomStringUtils;
import org.jboss.aerogear.security.otp.api.Base32;

import javax.persistence.*;
import javax.validation.constraints.NotBlank;
import java.util.Date;

@Entity
@Table(name = "user_account")
public class User {
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "user_sequence"
    )
    @SequenceGenerator(
            name = "user_sequence",
            allocationSize = 1
    )
    private Long id;
    @Column(
            updatable = false,
            unique = true
    )
    private String userId;
    @NotBlank(message = "First name is mandatory")
    private String firstName;
    @NotBlank(message = "Last name is mandatory")
    private String lastName;
    @NotBlank(message = "Display name is mandatory")
    private String displayName;
    private int tag;
    @NotBlank(message = "Email is mandatory")
    @ValidEmail
    private String email;
    @NotBlank(message = "Password is mandatory")
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    @ValidPassword
    private String password;
    private Date lastLoggedIn;
    private Date joinDate;
    @Enumerated(EnumType.STRING)
    private Role role;
    private boolean isUsing2FA;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String secret;
    private int refreshTokenCount;
    private boolean isActive;
    private boolean isEmailVerified;

    public User(String firstName, String lastName, String displayName, String email, String password, Date joinDate, Role role, boolean isActive, boolean isEmailVerified) {
        this.userId = RandomStringUtils.randomNumeric(10);
        this.firstName = firstName;
        this.lastName = lastName;
        this.displayName = displayName;
        this.tag = Integer.parseInt(RandomStringUtils.randomNumeric(4));
        this.email = email;
        this.password = password;
        this.joinDate = joinDate;
        this.role = role;
        this.isUsing2FA = false;
        this.secret = Base32.random();
        this.refreshTokenCount = 0;
        this.isActive = isActive;
        this.isEmailVerified = isEmailVerified;
    }

    public User() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public int getTag() {
        return tag;
    }

    public void setTag(int tag) {
        this.tag = tag;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Date getLastLoggedIn() {
        return lastLoggedIn;
    }

    public void setLastLoggedIn(Date lastLoggedIn) {
        this.lastLoggedIn = lastLoggedIn;
    }

    public Date getJoinDate() {
        return joinDate;
    }

    public void setJoinDate(Date joinDate) {
        this.joinDate = joinDate;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }

    public boolean isUsing2FA() {
        return isUsing2FA;
    }

    public void setUsing2FA(boolean using2FA) {
        isUsing2FA = using2FA;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public int getRefreshTokenCount() {
        return refreshTokenCount;
    }

    public void setRefreshTokenCount(int refreshTokenCount) {
        this.refreshTokenCount = refreshTokenCount;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean active) {
        isActive = active;
    }

    public boolean isEmailVerified() {
        return isEmailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        isEmailVerified = emailVerified;
    }
}
