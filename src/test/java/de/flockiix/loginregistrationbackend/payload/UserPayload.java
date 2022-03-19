package de.flockiix.loginregistrationbackend.payload;
public class UserPayload {
    private String firstName;
    private String lastName;
    private String displayName;
    private String email;
    private String password;

    public UserPayload(String firstName, String lastName, String displayName, String email, String password) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.displayName = displayName;
        this.email = email;
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public UserPayload setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getLastName() {
        return lastName;
    }

    public UserPayload setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public String getDisplayName() {
        return displayName;
    }

    public UserPayload setDisplayName(String displayName) {
        this.displayName = displayName;
        return this;
    }

    public String getEmail() {
        return email;
    }

    public UserPayload setEmail(String email) {
        this.email = email;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public UserPayload setPassword(String password) {
        this.password = password;
        return this;
    }
}
