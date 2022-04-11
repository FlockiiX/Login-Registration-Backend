package de.flockiix.loginregistrationbackend.google2fa;

import de.flockiix.loginregistrationbackend.cache.LoginAttemptCache;
import de.flockiix.loginregistrationbackend.model.BackupCode;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import de.flockiix.loginregistrationbackend.service.BackupCodeService;
import de.flockiix.loginregistrationbackend.util.Utils;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.transaction.Transactional;

@Transactional
public class CustomAuthenticationProvider extends DaoAuthenticationProvider {
    @Autowired
    private BackupCodeService backupCodeService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private LoginAttemptCache loginAttemptCache;
    @Autowired
    private UserRepository userRepository;

    @Override
    public Authentication authenticate(Authentication auth) throws AuthenticationException {
        User user = userRepository
                .findUserByEmail(auth.getName())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        loginAttemptCache.validateLoginAttempt(user);
        if (user.isUsing2FA()) {
            String verificationCode = ((CustomWebAuthenticationDetails) auth.getDetails()).getVerificationCode();
            Totp totp = new Totp(user.getSecret());
            if (!Utils.isValidLong(verificationCode) || !totp.verify(verificationCode)) {
                if (verificationCode == null || !matchesBackupCode(user, verificationCode)) {
                    throw new BadCredentialsException("Invalid code");
                }
            }
        }

        Authentication result = super.authenticate(auth);
        return new UsernamePasswordAuthenticationToken(user, result.getCredentials(), result.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return super.supports(authentication);
    }

    /**
     * Checks if the verification code matches an unused backup code.
     * If the verification code matches the backup code is saved as used and cannot be used again.
     *
     * @param user             the user
     * @param verificationCode the otp code
     * @return true if the verificationCode matches an unused backup code and false otherwise
     */
    private boolean matchesBackupCode(User user, String verificationCode) {
        boolean matches = false;
        for (BackupCode code : backupCodeService.getBackupCodesByUser(user)) {
            if (bCryptPasswordEncoder.matches(verificationCode, code.getCode())) {
                if (code.isUsed())
                    throw new BadCredentialsException("Backup code already used");
                matches = true;
                backupCodeService.setBackupCodeUsed(code);
            }
        }

        return matches;
    }
}
