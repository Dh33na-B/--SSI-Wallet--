package SSI.Wallet.Identity.model.entity;

import SSI.Wallet.Identity.model.enums.DocumentReviewRequestStatus;
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
        name = "document_review_requests",
        indexes = {
                @Index(name = "idx_doc_review_document", columnList = "document_id"),
                @Index(name = "idx_doc_review_holder", columnList = "holder_id"),
                @Index(name = "idx_doc_review_issuer", columnList = "issuer_id"),
                @Index(name = "idx_doc_review_status", columnList = "status")
        }
)
public class DocumentReviewRequestEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "document_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_doc_review_document")
    )
    private DocumentEntity document;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "holder_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_doc_review_holder")
    )
    private UserEntity holder;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "issuer_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_doc_review_issuer")
    )
    private UserEntity issuer;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 50, nullable = false)
    private DocumentReviewRequestStatus status = DocumentReviewRequestStatus.REQUESTED;

    @Column(name = "issuer_encryption_public_key", columnDefinition = "TEXT")
    private String issuerEncryptionPublicKey;

    @Column(name = "issuer_note", columnDefinition = "TEXT")
    private String issuerNote;

    @Column(name = "holder_note", columnDefinition = "TEXT")
    private String holderNote;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
