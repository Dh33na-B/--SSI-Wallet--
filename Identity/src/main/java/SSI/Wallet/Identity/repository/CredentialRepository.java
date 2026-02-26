package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.CredentialEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CredentialRepository extends JpaRepository<CredentialEntity, UUID> {

    Optional<CredentialEntity> findByCredentialId(String credentialId);

    List<CredentialEntity> findByDocumentUserId(UUID userId);

    List<CredentialEntity> findByIssuerId(UUID issuerId);

    List<CredentialEntity> findByRevoked(Boolean revoked);

    @Modifying
    @Query("update CredentialEntity c set c.issuer = null where c.issuer.id = :userId")
    int clearIssuerByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query("update CredentialEntity c set c.document = null where c.document.user.id = :userId")
    int clearDocumentByDocumentOwnerId(@Param("userId") UUID userId);
}
