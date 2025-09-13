package dev.slethware.montra.user;

import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.ResourceNotFoundException;
import dev.slethware.montra.shared.util.UsernameUtil;
import dev.slethware.montra.user.dto.UpdateUserProfileRequest;
import dev.slethware.montra.user.dto.UserRegistrationRequest;
import dev.slethware.montra.user.dto.UserResponse;
import dev.slethware.montra.user.model.Authority;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final UsernameUtil usernameUtil;

    @Override
    public User createUser(UserRegistrationRequest request) {
        log.info("Creating user with email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("User with this email already exists");
        }

        User user = User.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .username(request.getEmail()) // Default username to email
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .usernameCustomized(false)
                .usernameChangeCount(0)
                .usernameChangesThisYear(0)
                .usernameYearResetDate(LocalDate.now())
                .pinAttempts(0)
                .emailVerified(false)
                .accountSetupComplete(false)
                .enabled(false)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .canResetPassword(false)
                .build();

        // Assign default user authorities
        List<Authority> userAuthorities = authorityRepository.findAllByNameIn(List.of("ROLE_USER"));
        user.setAuthorities(userAuthorities);

        User savedUser = userRepository.save(user);
        log.info("User created successfully with ID: {} for email: {}", savedUser.getId(), savedUser.getEmail());
        return savedUser;
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        log.debug("Retrieving user by email: {}", email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        log.debug("Retrieving user by username: {}", username);
        return userRepository.findByUsernameIgnoreCase(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        log.debug("Retrieving user by ID: {}", id);
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public boolean doesUserExist(String email) {
        log.debug("Checking if user exists with email: {}", email);
        return userRepository.existsByEmail(email);
    }

    @Override
    public User saveUser(User user) {
        log.debug("Saving user with ID: {}", user.getId());
        User savedUser = userRepository.save(user);
        log.debug("User saved successfully with ID: {}", savedUser.getId());
        return savedUser;
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserResponse(User user) {
        log.debug("Building user response for user ID: {}", user.getId());

        List<String> authorityNames = getUserAuthorities(user).stream()
                .map(Authority::getName)
                .collect(Collectors.toList());

        UserResponse response = UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .bio(user.getBio())
                .role(user.getRole())
                .status(user.getStatus())
                .emailVerified(user.getEmailVerified())
                .accountSetupComplete(user.getAccountSetupComplete())
                .pinSet(user.isPinSet())
                .dateOfBirth(user.getDateOfBirth())
                .profilePictureUrl(user.getProfilePictureUrl())
                .usernameCustomized(user.getUsernameCustomized())
                .usernameLastChangedAt(user.getUsernameLastChangedAt())
                .usernameChangeCount(user.getUsernameChangeCount())
                .usernameChangesThisYear(user.getUsernameChangesThisYear())
                .authorities(authorityNames)
                .createdOn(user.getCreatedOn())
                .build();

        // Set display username (empty if same as email)
        response.setDisplayUsername(user.getUsername(), user.getEmail());

        return response;
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getPublicUserResponse(User user) {
        log.debug("Building public user response for user ID: {}", user.getId());
        UserResponse fullResponse = getUserResponse(user);
        return UserResponse.createPublicResponse(fullResponse);
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> getUserDetails(User user) {
        log.debug("Building user details for user ID: {}", user.getId());

        List<String> authorityNames = getUserAuthorities(user).stream()
                .map(Authority::getName)
                .collect(Collectors.toList());

        Map<String, Object> details = new HashMap<>();
        details.put("id", user.getId());
        details.put("email", user.getEmail());
        details.put("firstName", user.getFirstName());
        details.put("lastName", user.getLastName());
        details.put("fullName", user.getFullName());
        details.put("username", user.hasCustomizedUsername() ? user.getUsername() : "");
        details.put("bio", user.getBio());
        details.put("role", user.getRole());
        details.put("status", user.getStatus());
        details.put("emailVerified", user.getEmailVerified());
        details.put("accountSetupComplete", user.getAccountSetupComplete());
        details.put("pinSet", user.isPinSet());
        details.put("dateOfBirth", user.getDateOfBirth());
        details.put("profilePictureUrl", user.getProfilePictureUrl());
        details.put("authorities", authorityNames);
        return details;
    }

    @Override
    public User updateUserProfile(User currentUser, UpdateUserProfileRequest request) {
        log.info("Starting profile update for user ID: {}", currentUser.getId());

        User user = getUserById(currentUser.getId());

        // Handle username update
        if (request.isUsernameUpdate()) {
            validateUsernameChange(user, request.getUsername());
            handleUsernameUpdate(user, request.getUsername());
        }

        // Handle bio update
        if (request.isBioUpdate()) {
            user.setBio(request.getBio());
        }

        // Handle date of birth update
        if (request.isDateOfBirthUpdate()) {
            user.setDateOfBirth(request.getDateOfBirth());
        }

        // Handle profile picture update
        if (request.isProfilePictureUpdate()) {
            user.setProfilePictureUrl(request.getProfilePictureUrl());
        }

        User savedUser = userRepository.save(user);
        log.info("Profile updated successfully for user ID: {}", user.getId());
        return savedUser;
    }

    @Override
    public void setupUserPin(User user, String pin) {
        log.info("Starting PIN setup for user ID: {}", user.getId());

        if (!user.getEmailVerified()) {
            throw new BadRequestException("Email must be verified before setting up PIN");
        }

        String hashedPin = passwordEncoder.encode(pin);
        user.setupPin(hashedPin);
        user.completeAccountSetup();

        userRepository.save(user);
        emailService.sendPinSetupConfirmation(user.getEmail(), user.getFirstName());

        log.info("PIN setup completed successfully for user ID: {}", user.getId());
    }

    @Override
    public boolean validateUserPin(String email, String pin) {
        log.info("Starting PIN validation for user: {}", email);

        User user = getUserByEmail(email);

        if (!user.isPinSet()) {
            throw new BadRequestException("PIN is not set for this user");
        }

        if (!user.canAttemptPin()) {
            throw new BadRequestException("PIN attempts exceeded. Please try again later.");
        }

        boolean isValid = passwordEncoder.matches(pin, user.getPinHash());

        if (isValid) {
            user.recordSuccessfulPinAttempt();
            log.info("PIN validation successful for user: {}", email);
        } else {
            user.recordFailedPinAttempt();
            log.warn("PIN validation failed for user: {}. Attempts: {}", email, user.getPinAttempts());
        }

        userRepository.save(user);
        return isValid;
    }

    @Override
    public void verifyUserEmail(String email) {
        log.info("Starting email verification for user: {}", email);

        User user = getUserByEmail(email);
        user.verifyEmail();
        userRepository.save(user);

        log.info("Email verified successfully for user: {}", email);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getUsersByRole(UserRole role) {
        log.info("Retrieving users by role: {}", role);
        List<User> users = userRepository.findByRole(role);
        log.info("Found {} users with role: {}", users.size(), role);
        return users;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> getActiveUsersByRole(UserRole role, int page, int size) {
        log.info("Retrieving active users by role: {} (page: {}, size: {})", role, page, size);
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdOn").descending());
        Page<User> users = userRepository.findByRoleAndEmailVerifiedTrue(role, pageable);
        log.info("Found {} active users with role: {}", users.getTotalElements(), role);
        return users;
    }

    @Override
    public void assignAuthoritiesToUser(String email, List<String> authorityNames) {
        log.info("Starting authority assignment for user: {} - authorities: {}", email, authorityNames);

        User user = getUserByEmail(email);
        List<Authority> authorities = authorityRepository.findAllByNameIn(authorityNames);

        if (authorities.size() != authorityNames.size()) {
            throw new BadRequestException("One or more authorities not found");
        }

        List<Authority> currentAuthorities = new ArrayList<>(getUserAuthorities(user));
        currentAuthorities.addAll(authorities);
        user.setAuthorities(currentAuthorities);
        userRepository.save(user);

        log.info("Authorities {} assigned successfully to user: {}", authorityNames, email);
    }

    @Override
    public void removeAuthoritiesFromUser(String email, List<String> authorityNames) {
        log.info("Starting authority removal for user: {} - authorities: {}", email, authorityNames);

        User user = getUserByEmail(email);
        List<Authority> authoritiesToRemove = authorityRepository.findAllByNameIn(authorityNames);

        List<Authority> currentAuthorities = new ArrayList<>(getUserAuthorities(user));
        currentAuthorities.removeAll(authoritiesToRemove);
        user.setAuthorities(currentAuthorities);
        userRepository.save(user);

        log.info("Authorities {} removed successfully from user: {}", authorityNames, email);
    }

    @Override
    public void validateUsernameChange(User user, String newUsername) {
        log.info("Validating username change for user ID: {} to username: {}", user.getId(), newUsername);

        if (user.isAdmin()) {
            throw new BadRequestException("Admins cannot change their username");
        }

        if (newUsername.equals(user.getEmail())) {
            throw new BadRequestException("Username cannot be set back to email address");
        }

        // Check cooldown period
        if (user.getUsernameLastChangedAt() != null) {
            LocalDateTime cooldownEnd = user.getUsernameLastChangedAt().plusWeeks(2);
            if (LocalDateTime.now().isBefore(cooldownEnd)) {
                throw new BadRequestException("Username can only be changed every 2 weeks");
            }
        }

        // Check yearly limit
        LocalDate currentYear = LocalDate.now();
        if (user.getUsernameYearResetDate() == null ||
                user.getUsernameYearResetDate().getYear() < currentYear.getYear()) {
            // Reset yearly counter
            user.setUsernameChangesThisYear(0);
            user.setUsernameYearResetDate(currentYear);
        }

        if (user.getUsernameChangesThisYear() >= 5) {
            throw new BadRequestException("Maximum 5 username changes per year reached");
        }

        // Check format and uniqueness
        UsernameUtil.ValidationResult validation =
                usernameUtil.validateUsername(newUsername, user.getId());

        if (!validation.isValid()) {
            throw new BadRequestException(validation.getErrorMessage());
        }

        log.info("Username validation passed for user ID: {}", user.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean isUsernameAvailable(String username, Long excludeUserId) {
        log.debug("Checking username availability: {} (excluding user ID: {})", username, excludeUserId);
        UsernameUtil.ValidationResult validation =
                usernameUtil.validateUsername(username, excludeUserId);
        return validation.isValid();
    }


    // HELPERS
    private void handleUsernameUpdate(User user, String newUsername) {
        user.updateUsername(newUsername);
        log.info("Username updated for user ID: {} to: {}", user.getId(), newUsername);
    }

    private List<Authority> getUserAuthorities(User user) {
        if (user.getAuthorities() == null) {
            return new ArrayList<>();
        }
        return user.getAuthorities().stream()
                .map(authority -> (Authority) authority)
                .collect(Collectors.toList());
    }
}