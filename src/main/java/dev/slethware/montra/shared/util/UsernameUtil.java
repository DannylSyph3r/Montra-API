package dev.slethware.montra.shared.util;

import dev.slethware.montra.user.UserRepository;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.regex.Pattern;

@Component
@RequiredArgsConstructor
public class UsernameUtil {

    private final UserRepository userRepository;

    // Username validation pattern: 3-15 characters, international chars allowed, 
    // must start with letter/number, can contain letters/numbers/underscores
    private static final Pattern USERNAME_PATTERN = Pattern.compile(
            "^[\\p{L}\\p{N}][\\p{L}\\p{N}_]{2,14}$"
    );

    // Pattern to check if username is all numbers
    private static final Pattern ALL_NUMBERS_PATTERN = Pattern.compile("^\\d+$");

    // Reserved usernames that cannot be used
    private static final Set<String> RESERVED_USERNAMES = Set.of(
            "admin", "support", "help", "api", "root", "null", "undefined",
            "test", "user", "system", "service", "bot", "www", "ftp", "mail",
            "email", "info", "contact", "about", "terms", "privacy", "legal",
            "billing", "account", "profile", "settings", "config", "dev",
            "developer", "team", "staff", "moderator", "mod", "owner"
    );

    // Validates username format and business rules
    public ValidationResult validateUsername(String username, Long currentUserId) {
        if (username == null || username.trim().isEmpty()) {
            return ValidationResult.error("Username is required");
        }

        username = username.trim();

        // Length and character validation
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            return ValidationResult.error(
                    "Username must be 3-15 characters, start with letter/number, " +
                            "and contain only letters, numbers, and underscores"
            );
        }

        // Cannot be all numbers
        if (ALL_NUMBERS_PATTERN.matcher(username).matches()) {
            return ValidationResult.error("Username cannot be all numbers");
        }

        // Reserved words check (case-insensitive)
        if (RESERVED_USERNAMES.contains(username.toLowerCase())) {
            return ValidationResult.error("This username is not available");
        }

        // Uniqueness check (case-insensitive)
        if (isUsernameTaken(username, currentUserId)) {
            return ValidationResult.error("Username is already taken");
        }

        return ValidationResult.success();
    }

    // Check if username is already taken by another user (case-insensitive)
    private boolean isUsernameTaken(String username, Long currentUserId) {
        return userRepository.findByUsernameIgnoreCase(username)
                .map(user -> !user.getId().equals(currentUserId))
                .orElse(false);
    }

    // Normalize username for case-insensitive comparison
    public String normalizeUsername(String username) {
        return username != null ? username.toLowerCase() : null;
    }

    // Check if username follows the basic format rules (without checking uniqueness)
    public boolean isValidFormat(String username) {
        if (username == null || username.trim().isEmpty()) {
            return false;
        }

        username = username.trim();
        return USERNAME_PATTERN.matcher(username).matches() &&
                !ALL_NUMBERS_PATTERN.matcher(username).matches() &&
                !RESERVED_USERNAMES.contains(username.toLowerCase());
    }

    // Result class for validation operations
    @Getter
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;

        private ValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult error(String message) {
            return new ValidationResult(false, message);
        }

    }
}