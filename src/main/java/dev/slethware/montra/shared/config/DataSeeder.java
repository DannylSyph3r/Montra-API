package dev.slethware.montra.shared.config;

import dev.slethware.montra.user.AuthorityRepository;
import dev.slethware.montra.user.UserRepository;
import dev.slethware.montra.user.model.Authority;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Profile("dev")
@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private static final String[] BASIC_ROLES = {
            "ROLE_USER",
            "ROLE_ADMIN",
            "ROLE_SUPER_ADMIN"
    };

    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${montra.admin.email:admin@montra.dev}")
    private String adminEmail;

    @Value("${montra.admin.password:admin123}")
    private String adminPassword;

    @Override
    @Transactional
    public void run(String... args) {
        log.info("Starting data seeding...");

        seedBasicRoles();
        seedAdminUser();

        log.info("Data seeding completed");
    }

    private void seedBasicRoles() {
        if (authorityRepository.count() == 0) {
            for (String roleName : BASIC_ROLES) {
                if (authorityRepository.findByName(roleName).isEmpty()) {
                    Authority authority = Authority.builder()
                            .name(roleName)
                            .description("Basic role: " + roleName)
                            .build();
                    authorityRepository.save(authority);
                }
            }
            log.info("Seeded {} basic roles", BASIC_ROLES.length);
        }
    }

    private void seedAdminUser() {
        if (userRepository.count() == 0) {
            User admin = User.builder()
                    .email(adminEmail)
                    .firstName("Admin")
                    .lastName("User")
                    .passwordHash(passwordEncoder.encode(adminPassword))
                    .role(UserRole.SUPER_ADMIN)
                    .emailVerified(true)
                    .enabled(true)
                    .accountNonLocked(true)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .accountSetupComplete(true)
                    .build();

            // Assign super admin role
            List<Authority> adminAuthorities = authorityRepository.findAllByNameIn(
                    List.of("ROLE_SUPER_ADMIN")
            );
            admin.setAuthorities(adminAuthorities);

            userRepository.save(admin);
            log.info("Seeded admin user with email: {}", adminEmail);
        }
    }
}