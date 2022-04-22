package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.model.UserPrincipal;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository
                .findUserByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("No user found by email: " + email));

        user.setLastLoggedIn(new Date());
        return new UserPrincipal(user);
    }
}
