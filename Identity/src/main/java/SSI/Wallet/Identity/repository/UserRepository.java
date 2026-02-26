package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    Optional<UserEntity> findByWalletAddress(String walletAddress);

    Optional<UserEntity> findByWalletAddressIgnoreCase(String walletAddress);

    Optional<UserEntity> findByIdAndRole(UUID id, UserRole role);

    List<UserEntity> findByRoleOrderByCreatedAtAsc(UserRole role);

    List<UserEntity> findByRoleAndEncryptionPublicKeyIsNotNullOrderByCreatedAtAsc(UserRole role);
}
