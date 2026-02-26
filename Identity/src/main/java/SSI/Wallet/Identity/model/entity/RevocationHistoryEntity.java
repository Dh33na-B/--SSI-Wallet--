package SSI.Wallet.Identity.model.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Entity
@Table(
        name = "revocation_history",
        indexes = {
                @Index(name = "idx_revocation_credential", columnList = "credential_id")
        }
)
public class RevocationHistoryEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "credential_id",
            referencedColumnName = "credential_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_revocation_credential")
    )
    private CredentialEntity credential;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "revoked_by",
            foreignKey = @ForeignKey(name = "fk_revocation_user")
    )
    private UserEntity revokedBy;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    @CreationTimestamp
    @Column(name = "revoked_at", nullable = false, updatable = false)
    private LocalDateTime revokedAt;
}
