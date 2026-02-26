package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditLogRepository extends JpaRepository<AuditLogEntity, UUID> {

    List<AuditLogEntity> findByUserIdOrderByCreatedAtDesc(UUID userId);

    List<AuditLogEntity> findAllByOrderByCreatedAtDesc();

    @Modifying
    @Query("update AuditLogEntity al set al.user = null where al.user.id = :userId")
    int clearUserByUserId(@Param("userId") UUID userId);
}
