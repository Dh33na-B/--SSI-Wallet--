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
import jakarta.persistence.UniqueConstraint;
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
        name = "credentials",
        indexes = {
                @Index(name = "idx_credentials_doc", columnList = "document_id"),
                @Index(name = "idx_credentials_hash", columnList = "vc_hash"),
                @Index(name = "idx_credentials_revoked", columnList = "revoked"),
                @Index(name = "idx_credentials_issuer", columnList = "issuer_id")
        },
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_credentials_credential_id", columnNames = "credential_id")
        }
)
public class CredentialEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "document_id",
            foreignKey = @ForeignKey(name = "fk_credentials_document")
    )
    private DocumentEntity document;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(
            name = "issuer_id",
            foreignKey = @ForeignKey(name = "fk_credentials_issuer")
    )
    private UserEntity issuer;

    @Column(name = "credential_id", length = 150, nullable = false, unique = true)
    private String credentialId;

    @Column(name = "vc_ipfs_cid", nullable = false, columnDefinition = "TEXT")
    private String vcIpfsCid;

    @Column(name = "vc_hash", length = 256, nullable = false)
    private String vcHash;

    @Column(name = "blockchain_tx_hash", length = 256)
    private String blockchainTxHash;

    @Builder.Default
    @Column(name = "revoked", nullable = false)
    private Boolean revoked = Boolean.FALSE;

    @CreationTimestamp
    @Column(name = "issued_at", nullable = false, updatable = false)
    private LocalDateTime issuedAt;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;
}
