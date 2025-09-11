package dev.slethware.montra.user;

import dev.slethware.montra.user.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {

    Optional<Authority> findByName(String name);

    List<Authority> findAllByNameIn(List<String> names);

    boolean existsByName(String name);
}
