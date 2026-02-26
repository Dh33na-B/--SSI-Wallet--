package SSI.Wallet.Identity.repository;

import SSI.Wallet.Identity.model.entity.DocumentTypeEntity;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface DocumentTypeRepository extends JpaRepository<DocumentTypeEntity, UUID> {

    Optional<DocumentTypeEntity> findByNameIgnoreCase(String name);

    List<DocumentTypeEntity> findAllByOrderByNameAsc();

    @Modifying
    @Query("update DocumentTypeEntity dt set dt.createdBy = null where dt.createdBy.id = :userId")
    int clearCreatedByUserId(@Param("userId") UUID userId);
}
