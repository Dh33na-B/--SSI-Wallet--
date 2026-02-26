package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.CredentialEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialRepository extends JpaRepository<CredentialEntity, UUID> {

    Optional<CredentialEntity> findByCredentialId(String credentialId);

    List<CredentialEntity> findByDocumentUserId(UUID userId);

    List<CredentialEntity> findByIssuerId(UUID issuerId);

    List<CredentialEntity> findByRevoked(Boolean revoked);
}
