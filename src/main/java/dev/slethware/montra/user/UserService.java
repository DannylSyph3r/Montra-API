package dev.slethware.montra.user;

import dev.slethware.montra.user.dto.UpdateUserProfileRequest;
import dev.slethware.montra.user.dto.UserRegistrationRequest;
import dev.slethware.montra.user.dto.UserResponse;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.Map;

public interface UserService {

    // User registration and retrieval
    User createUser(UserRegistrationRequest request);
    User getUserByEmail(String email);
    User getUserByUsername(String username);
    User getUserById(Long id);
    boolean doesUserExist(String email);
    User saveUser(User user);

    // User responses and details
    UserResponse getUserResponse(User user);
    UserResponse getPublicUserResponse(User user);
    Map<String, Object> getUserDetails(User user);

    // Profile management
    User updateUserProfile(User currentUser, UpdateUserProfileRequest request);

    // PIN management
    void setupUserPin(User user, String pin);
    boolean validateUserPin(String email, String pin);

    // Email verification
    void verifyUserEmail(String email);

    // User queries
    List<User> getUsersByRole(UserRole role);
    Page<User> getActiveUsersByRole(UserRole role, int page, int size);

    // Authority management
    void assignAuthoritiesToUser(String email, List<String> authorityNames);
    void removeAuthoritiesFromUser(String email, List<String> authorityNames);

    // Username management
    void validateUsernameChange(User user, String newUsername);
    boolean isUsernameAvailable(String username, Long excludeUserId);
}