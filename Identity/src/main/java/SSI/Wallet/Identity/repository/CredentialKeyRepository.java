package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.CredentialKeyEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CredentialKeyRepository extends JpaRepository<CredentialKeyEntity, UUID> {

    Optional<CredentialKeyEntity> findTopByCredentialIdAndRecipientUserIdOrderByCreatedAtDesc(
            UUID credentialId,
            UUID recipientUserId
    );

    @Modifying
    @Query("update CredentialKeyEntity ck set ck.recipientUser = null where ck.recipientUser.id = :userId")
    int clearRecipientUserByUserId(@Param("userId") UUID userId);
}
