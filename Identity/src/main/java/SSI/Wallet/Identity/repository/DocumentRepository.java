package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.enums.DocumentStatus;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DocumentRepository extends JpaRepository<DocumentEntity, UUID> {

    List<DocumentEntity> findByUserId(UUID userId);

    List<DocumentEntity> findByStatus(DocumentStatus status);

    long deleteByUserId(UUID userId);
}
