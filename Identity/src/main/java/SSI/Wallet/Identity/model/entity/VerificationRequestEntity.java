package SSI.Wallet.Identity.model.entity;

import SSI.Wallet.Identity.model.enums.VerificationRequestStatus;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
import org.hibernate.annotations.UpdateTimestamp;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
@Entity
@Table(
        name = "verification_requests",
        indexes = {
                @Index(name = "idx_verif_req_verifier", columnList = "verifier_id"),
                @Index(name = "idx_verif_req_holder", columnList = "holder_id"),
                @Index(name = "idx_verif_req_credential", columnList = "credential_ref_id"),
                @Index(name = "idx_verif_req_status", columnList = "status")
        }
)
public class VerificationRequestEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "credential_ref_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_verif_req_credential")
    )
    private CredentialEntity credential;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "holder_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_verif_req_holder")
    )
    private UserEntity holder;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "verifier_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_verif_req_verifier")
    )
    private UserEntity verifier;

    @Column(name = "requested_fields", nullable = false, columnDefinition = "TEXT")
    private String requestedFields;

    @Column(name = "disclosed_fields", columnDefinition = "TEXT")
    private String disclosedFields;

    @Column(name = "purpose", columnDefinition = "TEXT")
    private String purpose;

    @Column(name = "proof_value", columnDefinition = "TEXT")
    private String proofValue;

    @Column(name = "proof_nonce", columnDefinition = "TEXT")
    private String proofNonce;

    @Column(name = "revealed_messages", columnDefinition = "TEXT")
    private String revealedMessages;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 40, nullable = false)
    private VerificationRequestStatus status = VerificationRequestStatus.REQUESTED;

    @Column(name = "verification_status")
    private Boolean verificationStatus;

    @Column(name = "signature_valid")
    private Boolean signatureValid;

    @Column(name = "blockchain_anchored")
    private Boolean blockchainAnchored;

    @Column(name = "blockchain_revoked")
    private Boolean blockchainRevoked;

    @Column(name = "vc_hash_matches")
    private Boolean vcHashMatches;

    @Column(name = "verification_message", columnDefinition = "TEXT")
    private String verificationMessage;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "responded_at")
    private LocalDateTime respondedAt;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}

