package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentKeyRepository extends JpaRepository<DocumentKeyEntity, UUID> {

    List<DocumentKeyEntity> findByDocumentId(UUID documentId);

    List<DocumentKeyEntity> findByRecipientUserId(UUID recipientUserId);
}
