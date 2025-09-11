package dev.slethware.montra.user;

import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.ResourceNotFoundException;
import dev.slethware.montra.user.dto.CompleteAccountSetupRequest;
import dev.slethware.montra.user.dto.UserProfileUpdateRequest;
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

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

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
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(UserRole.USER)
                .build();

        // Assign default user authorities
        List<Authority> userAuthorities = authorityRepository.findAllByNameIn(List.of("ROLE_USER"));
        user.setAuthorities(userAuthorities);

        return userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with id: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserResponse(User user) {
        return UserResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .role(user.getRole())
                .status(user.getStatus())
                .emailVerified(user.isEmailVerified())
                .accountSetupComplete(user.isAccountSetupComplete())
                .pinSet(user.isPinSet())
                .dateOfBirth(user.getDateOfBirth())
                .profilePictureUrl(user.getProfilePictureUrl())
                .authorities(user.getAuthorities().stream()
                        .map(Authority::getName)
                        .toList())
                .createdOn(user.getCreatedOn())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public Map<String, Object> getUserDetails(User user) {
        Map<String, Object> details = new HashMap<>();
        details.put("id", user.getId());
        details.put("email", user.getEmail());
        details.put("firstName", user.getFirstName());
        details.put("lastName", user.getLastName());
        details.put("fullName", user.getFullName());
        details.put("username", user.getUsername());
        details.put("role", user.getRole());
        details.put("status", user.getStatus());
        details.put("emailVerified", user.isEmailVerified());
        details.put("accountSetupComplete", user.isAccountSetupComplete());
        details.put("pinSet", user.isPinSet());
        details.put("dateOfBirth", user.getDateOfBirth());
        details.put("profilePictureUrl", user.getProfilePictureUrl());
        details.put("authorities", user.getAuthorities().stream()
                .map(Authority::getName)
                .toList());
        return details;
    }

    @Override
    public User updateUserProfile(UserProfileUpdateRequest request) {
        User user = getUserByEmail(request.getEmail());

        if (request.getUsername() != null && !request.getUsername().equals(user.getUsername())) {
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new BadRequestException("Username already exists");
            }
            user.setUsername(request.getUsername());
        }

        if (request.getDateOfBirth() != null) {
            user.setDateOfBirth(request.getDateOfBirth());
        }

        if (request.getProfilePictureUrl() != null) {
            user.setProfilePictureUrl(request.getProfilePictureUrl());
        }

        return userRepository.save(user);
    }

    @Override
    public void setupUserPin(User user, String pin) {
        log.info("Setting up PIN for user: {}", user.getEmail());

        if (!user.isEmailVerified()) {
            throw new BadRequestException("Email must be verified before setting up PIN");
        }

        String hashedPin = passwordEncoder.encode(pin);
        user.setupPin(hashedPin);

        userRepository.save(user);

        // Send PIN setup confirmation email
        emailService.sendPinSetupConfirmation(user.getEmail(), user.getFirstName());

        log.info("PIN setup completed for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public boolean validateUserPin(String email, String pin) {
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
    public void completeUserAccountSetup(User user, CompleteAccountSetupRequest request) {
        log.info("Completing account setup for user: {}", user.getEmail());

        if (request.getUsername() != null && !request.getUsername().trim().isEmpty()) {
            if (userRepository.existsByUsername(request.getUsername())) {
                throw new BadRequestException("Username already exists");
            }
            user.setUsername(request.getUsername());
        }

        if (request.getDateOfBirth() != null) {
            user.setDateOfBirth(request.getDateOfBirth());
        }

        if (request.getProfilePictureUrl() != null) {
            user.setProfilePictureUrl(request.getProfilePictureUrl());
        }

        user.completeAccountSetup();
        userRepository.save(user);

        // Send account setup complete email
        emailService.sendAccountSetupComplete(user.getEmail(), user.getFirstName());

        log.info("Account setup completed for user: {}", user.getEmail());
    }

    @Override
    @Transactional(readOnly = true)
    public boolean doesUserExist(String email) {
        return userRepository.existsByEmail(email);
    }

    @Override
    public User saveUser(User user) {
        return userRepository.save(user);
    }

    @Override
    public void verifyUserEmail(String email) {
        User user = getUserByEmail(email);
        user.verifyEmail();
        userRepository.save(user);
        log.info("Email verified for user: {}", email);
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getUsersByRole(UserRole role) {
        return userRepository.findByRole(role);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<User> getActiveUsersByRole(UserRole role, int page, int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdOn").descending());
        return userRepository.findByRoleAndEmailVerifiedTrue(role, pageable);
    }

    @Override
    public void assignAuthoritiesToUser(String email, List<String> authorityNames) {
        User user = getUserByEmail(email);
        List<Authority> authorities = authorityRepository.findAllByNameIn(authorityNames);

        if (authorities.size() != authorityNames.size()) {
            throw new BadRequestException("One or more authorities not found");
        }

        // Add new authorities to existing ones
        user.getAuthorities().addAll(authorities);
        userRepository.save(user);

        log.info("Authorities {} assigned to user: {}", authorityNames, email);
    }

    @Override
    public void removeAuthoritiesFromUser(String email, List<String> authorityNames) {
        User user = getUserByEmail(email);
        List<Authority> authoritiesToRemove = authorityRepository.findAllByNameIn(authorityNames);

        user.getAuthorities().removeAll(authoritiesToRemove);
        userRepository.save(user);

        log.info("Authorities {} removed from user: {}", authorityNames, email);
    }
}