package SSI.Wallet.Identity.service;

import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import java.util.List;
import java.util.UUID;

public interface AuditorService {

    List<AuditLogEntity> getAuditLogs(UUID auditorId);

    List<RevocationHistoryEntity> getRevocationHistory(UUID auditorId);

    List<ProofLogEntity> getProofLogs(UUID auditorId);
}
