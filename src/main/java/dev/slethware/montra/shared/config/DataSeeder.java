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
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataSeeder implements CommandLineRunner {

    private final AuthorityRepository authorityRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${montra.admin.email:superadmin@montra.dev}")
    private String superAdminEmail;

    @Value("${montra.admin.password:MontraAdmin2024!}")
    private String superAdminPassword;

    @Value("${montra.admin.first-name:Super}")
    private String superAdminFirstName;

    @Value("${montra.admin.last-name:Admin}")
    private String superAdminLastName;

    // Define all authorities/permissions in the system
    private final String[] authorities = {
            // Role-based authorities
            "ROLE_USER",
            "ROLE_ADMIN",
            "ROLE_SUPER_ADMIN",

            // Feature-based authorities for users
            "FEATURE_BASIC_TRANSACTIONS",
            "FEATURE_ADVANCED_ANALYTICS",
            "FEATURE_EXPORT_DATA",
            "FEATURE_MULTIPLE_ACCOUNTS",
            "FEATURE_BUDGET_PLANNING",
            "FEATURE_BILL_REMINDERS",
            "FEATURE_INVESTMENT_TRACKING",
            "FEATURE_GOAL_SETTING",
            "FEATURE_FINANCIAL_REPORTS",
            "FEATURE_CUSTOM_CATEGORIES",

            // Feature-based authorities for admins
            "FEATURE_SUPPORT_ACCESS",
            "FEATURE_ANALYTICS_VIEW",
            "FEATURE_USER_MANAGEMENT",
            "FEATURE_SYSTEM_CONFIG",
            "FEATURE_AUDIT_LOGS",
            "FEATURE_FINANCIAL_OVERSIGHT",

            // Plan-based authorities (for future subscription plans)
            "PLAN_FREE",
            "PLAN_PREMIUM",
            "PLAN_PROFESSIONAL",
            "PLAN_ENTERPRISE"
    };

    @Override
    public void run(String... args) {
        log.info("Starting data seeding process...");

        try {
            seedAuthorities();
            seedSuperAdmin();

            log.info("Data seeding completed successfully");
        } catch (Exception e) {
            log.error("Error occurred during data seeding: {}", e.getMessage(), e);
        }
    }

    private void seedAuthorities() {
        log.info("Seeding authorities...");

        if (authorityRepository.count() == 0) {
            List<Authority> authoritiesToSave = new ArrayList<>();

            for (String authorityName : authorities) {
                if (authorityRepository.findByName(authorityName).isEmpty()) {
                    Authority authority = Authority.builder()
                            .name(authorityName)
                            .description(getAuthorityDescription(authorityName))
                            .build();
                    authoritiesToSave.add(authority);
                }
            }

            if (!authoritiesToSave.isEmpty()) {
                authorityRepository.saveAll(authoritiesToSave);
                log.info("Seeded {} authorities", authoritiesToSave.size());
            }
        } else {
            log.info("Authorities already exist, skipping seeding");
        }
    }

    private void seedSuperAdmin() {
        log.info("Seeding super admin user...");

        if (userRepository.count() == 0) {
            // Create super admin user
            User superAdmin = User.builder()
                    .email(superAdminEmail)
                    .firstName(superAdminFirstName)
                    .lastName(superAdminLastName)
                    .passwordHash(passwordEncoder.encode(superAdminPassword))
                    .role(UserRole.SUPER_ADMIN)
                    .emailVerified(true)
                    .enabled(true)
                    .accountNonLocked(true)
                    .accountNonExpired(true)
                    .credentialsNonExpired(true)
                    .accountSetupComplete(true)
                    .build();

            // Assign super admin authorities
            List<Authority> superAdminAuthorities = authorityRepository.findAllByNameIn(List.of(
                    "ROLE_SUPER_ADMIN",
                    "FEATURE_SUPPORT_ACCESS",
                    "FEATURE_ANALYTICS_VIEW",
                    "FEATURE_USER_MANAGEMENT",
                    "FEATURE_SYSTEM_CONFIG",
                    "FEATURE_AUDIT_LOGS",
                    "FEATURE_FINANCIAL_OVERSIGHT"
            ));

            superAdmin.setAuthorities(superAdminAuthorities);
            userRepository.save(superAdmin);

            log.info("Super admin user created successfully with email: {}", superAdminEmail);
            log.info("Super admin password: {}", superAdminPassword);
            log.warn("Please change the super admin password after first login!");
        } else {
            log.info("Users already exist, skipping super admin creation");
        }
    }

    private String getAuthorityDescription(String authorityName) {
        return switch (authorityName) {
            // Roles
            case "ROLE_USER" -> "Basic user role with standard permissions";
            case "ROLE_ADMIN" -> "Administrative role with elevated permissions";
            case "ROLE_SUPER_ADMIN" -> "Super administrator with full system access";

            // User features
            case "FEATURE_BASIC_TRANSACTIONS" -> "Access to basic transaction recording and viewing";
            case "FEATURE_ADVANCED_ANALYTICS" -> "Access to advanced financial analytics and insights";
            case "FEATURE_EXPORT_DATA" -> "Ability to export transaction data";
            case "FEATURE_MULTIPLE_ACCOUNTS" -> "Support for multiple financial accounts";
            case "FEATURE_BUDGET_PLANNING" -> "Budget creation and tracking features";
            case "FEATURE_BILL_REMINDERS" -> "Bill reminder and notification features";
            case "FEATURE_INVESTMENT_TRACKING" -> "Investment portfolio tracking";
            case "FEATURE_GOAL_SETTING" -> "Financial goal setting and tracking";
            case "FEATURE_FINANCIAL_REPORTS" -> "Detailed financial report generation";
            case "FEATURE_CUSTOM_CATEGORIES" -> "Custom transaction categorization";

            // Admin features
            case "FEATURE_SUPPORT_ACCESS" -> "Access to customer support dashboard";
            case "FEATURE_ANALYTICS_VIEW" -> "View system-wide analytics and statistics";
            case "FEATURE_USER_MANAGEMENT" -> "Manage user accounts and permissions";
            case "FEATURE_SYSTEM_CONFIG" -> "System configuration and settings management";
            case "FEATURE_AUDIT_LOGS" -> "Access to system audit logs";
            case "FEATURE_FINANCIAL_OVERSIGHT" -> "Oversight of financial data and compliance";

            // Plans
            case "PLAN_FREE" -> "Free plan limitations and features";
            case "PLAN_PREMIUM" -> "Premium plan features and limits";
            case "PLAN_PROFESSIONAL" -> "Professional plan features and limits";
            case "PLAN_ENTERPRISE" -> "Enterprise plan features and limits";

            default -> "System permission: " + authorityName;
        };
    }
}