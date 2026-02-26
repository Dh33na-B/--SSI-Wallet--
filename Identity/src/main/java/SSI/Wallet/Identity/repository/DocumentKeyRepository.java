package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface DocumentKeyRepository extends JpaRepository<DocumentKeyEntity, UUID> {

    List<DocumentKeyEntity> findByDocumentId(UUID documentId);

    List<DocumentKeyEntity> findByRecipientUserId(UUID recipientUserId);

    long deleteByDocumentUserId(UUID userId);

    @Modifying
    @Query("update DocumentKeyEntity dk set dk.recipientUser = null where dk.recipientUser.id = :userId")
    int clearRecipientUserByUserId(@Param("userId") UUID userId);
}
