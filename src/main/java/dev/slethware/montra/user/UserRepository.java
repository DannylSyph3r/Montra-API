package dev.slethware.montra.user;

import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    List<User> findByRole(UserRole role);

    @Query("SELECT u FROM User u WHERE u.role IN :roles")
    List<User> findByRoles(@Param("roles") List<UserRole> roles);

    Page<User> findByRoleAndEmailVerifiedTrue(UserRole role, Pageable pageable);

    @Query("SELECT u FROM User u WHERE u.emailVerified = true AND u.enabled = true")
    List<User> findAllActiveUsers();
}