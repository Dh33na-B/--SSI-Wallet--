package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, UUID> {

    List<AuditLogEntity> findByUserIdOrderByCreatedAtDesc(UUID userId);

    List<AuditLogEntity> findAllByOrderByCreatedAtDesc();
}
