package dev.slethware.montra.user.model;

import dev.slethware.montra.shared.audit.Auditable;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;

@Data
@Entity
@Table(name = "authorities", indexes = {
        @Index(name = "authority_name_idx", columnList = "name", unique = true)
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Authority extends Auditable implements GrantedAuthority {

    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @Override
    public String getAuthority() {
        return name;
    }
}
