package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface RevocationHistoryRepository extends JpaRepository<RevocationHistoryEntity, UUID> {

    List<RevocationHistoryEntity> findByCredentialCredentialIdOrderByRevokedAtDesc(String credentialId);

    List<RevocationHistoryEntity> findAllByOrderByRevokedAtDesc();

    @Modifying
    @Query("update RevocationHistoryEntity rh set rh.revokedBy = null where rh.revokedBy.id = :userId")
    int clearRevokedByUserId(@Param("userId") UUID userId);
}
