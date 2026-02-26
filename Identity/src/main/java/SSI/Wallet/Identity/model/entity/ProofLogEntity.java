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
        name = "proof_logs",
        indexes = {
                @Index(name = "idx_proof_logs_credential", columnList = "credential_id")
        }
)
public class ProofLogEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "credential_id",
            referencedColumnName = "credential_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_proof_logs_credential")
    )
    private CredentialEntity credential;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "verifier_id",
            foreignKey = @ForeignKey(name = "fk_proof_logs_verifier")
    )
    private UserEntity verifier;

    @Column(name = "verification_status")
    private Boolean verificationStatus;

    @CreationTimestamp
    @Column(name = "verified_at", nullable = false, updatable = false)
    private LocalDateTime verifiedAt;
}
