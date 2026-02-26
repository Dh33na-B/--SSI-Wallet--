package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RevocationHistoryRepository extends JpaRepository<RevocationHistoryEntity, UUID> {

    List<RevocationHistoryEntity> findByCredentialCredentialIdOrderByRevokedAtDesc(String credentialId);

    List<RevocationHistoryEntity> findAllByOrderByRevokedAtDesc();
}
