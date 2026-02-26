package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.VerificationRequestEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface VerificationRequestRepository extends JpaRepository<VerificationRequestEntity, UUID> {

    List<VerificationRequestEntity> findByVerifierIdOrderByCreatedAtDesc(UUID verifierId);

    List<VerificationRequestEntity> findByHolderIdOrderByCreatedAtDesc(UUID holderId);

    Optional<VerificationRequestEntity> findByIdAndHolderId(UUID id, UUID holderId);

    Optional<VerificationRequestEntity> findByIdAndVerifierId(UUID id, UUID verifierId);

    long deleteByVerifierIdOrHolderId(UUID verifierId, UUID holderId);
}
