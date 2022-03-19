package de.flockiix.loginregistrationbackend.enumeration;

public enum Role {
    SUPER_USER("verified", "user:read", "user:update", "user:delete"),
    ADMIN("verified", "user:read", "user:update"),
    USER("verified"),
    UNVERIFIED();

    private final String[] authorities;

    Role(String... authorities) {
        this.authorities = authorities;
    }

    public String[] getAuthorities() {
        return authorities;
    }
}
