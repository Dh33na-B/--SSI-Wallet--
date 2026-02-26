package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.DocumentReviewRequestEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentReviewRequestRepository extends JpaRepository<DocumentReviewRequestEntity, UUID> {

    List<DocumentReviewRequestEntity> findByHolderIdOrderByUpdatedAtDesc(UUID holderId);

    List<DocumentReviewRequestEntity> findByIssuerIdOrderByUpdatedAtDesc(UUID issuerId);

    Optional<DocumentReviewRequestEntity> findByIdAndHolderId(UUID id, UUID holderId);

    Optional<DocumentReviewRequestEntity> findTopByDocumentIdAndIssuerIdOrderByCreatedAtDesc(
            UUID documentId,
            UUID issuerId
    );

    long deleteByIssuerIdOrHolderId(UUID issuerId, UUID holderId);
}
