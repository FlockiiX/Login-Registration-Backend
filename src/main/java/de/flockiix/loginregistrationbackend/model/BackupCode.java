package de.flockiix.loginregistrationbackend.model;

import javax.persistence.*;

@Entity
public class BackupCode {
    @Id
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "backupcode_sequence"
    )
    @SequenceGenerator(
            name = "backupcode_sequence",
            allocationSize = 1
    )
    private Long id;
    private String code;
    private boolean isUsed;
    @ManyToOne(
            targetEntity = User.class,
            fetch = FetchType.EAGER
    )
    @JoinColumn(
            nullable = false,
            name = "user_id"
    )
    private User user;

    public BackupCode(String code, User user) {
        this.code = code;
        this.isUsed = false;
        this.user = user;
    }

    public BackupCode() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public boolean isUsed() {
        return isUsed;
    }

    public void setUsed(boolean used) {
        isUsed = used;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
