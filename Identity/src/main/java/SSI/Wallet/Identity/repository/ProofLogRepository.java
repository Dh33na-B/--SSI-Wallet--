package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProofLogRepository extends JpaRepository<ProofLogEntity, UUID> {

    List<ProofLogEntity> findByCredentialCredentialIdOrderByVerifiedAtDesc(String credentialId);

    List<ProofLogEntity> findAllByOrderByVerifiedAtDesc();
}
