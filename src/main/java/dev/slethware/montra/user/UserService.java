package dev.slethware.montra.user;

import dev.slethware.montra.user.dto.UserProfileUpdateRequest;
import dev.slethware.montra.user.dto.UserRegistrationRequest;
import dev.slethware.montra.user.dto.UserResponse;
import dev.slethware.montra.user.dto.CompleteAccountSetupRequest;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import org.springframework.data.domain.Page;

import java.util.List;
import java.util.Map;

public interface UserService {

    User createUser(UserRegistrationRequest request);

    User getUserByEmail(String email);

    User getUserById(Long id);

    UserResponse getUserResponse(User user);

    Map<String, Object> getUserDetails(User user);

    User updateUserProfile(UserProfileUpdateRequest request);

    void setupUserPin(User user, String pin);

    boolean validateUserPin(String email, String pin);

    void completeUserAccountSetup(User user, CompleteAccountSetupRequest request);

    boolean doesUserExist(String email);

    User saveUser(User user);

    void verifyUserEmail(String email);

    List<User> getUsersByRole(UserRole role);

    Page<User> getActiveUsersByRole(UserRole role, int page, int size);

    void assignAuthoritiesToUser(String email, List<String> authorityNames);

    void removeAuthoritiesFromUser(String email, List<String> authorityNames);
}