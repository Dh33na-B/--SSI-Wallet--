package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ProofLogRepository extends JpaRepository<ProofLogEntity, UUID> {

    List<ProofLogEntity> findByCredentialCredentialIdOrderByVerifiedAtDesc(String credentialId);

    List<ProofLogEntity> findByVerifierIdOrderByVerifiedAtDesc(UUID verifierId);

    Optional<ProofLogEntity> findTopByVerificationRequestIdOrderByVerifiedAtDesc(UUID verificationRequestId);

    List<ProofLogEntity> findAllByOrderByVerifiedAtDesc();

    @Modifying
    @Query("update ProofLogEntity pl set pl.verifier = null where pl.verifier.id = :userId")
    int clearVerifierByUserId(@Param("userId") UUID userId);
}
