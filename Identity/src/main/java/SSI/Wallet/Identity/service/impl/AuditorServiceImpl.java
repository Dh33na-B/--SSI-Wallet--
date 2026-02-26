package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.ProofLogRepository;
import SSI.Wallet.Identity.repository.RevocationHistoryRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.AuditorService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuditorServiceImpl implements AuditorService {

    private final UserRepository userRepository;
    private final AuditLogRepository auditLogRepository;
    private final RevocationHistoryRepository revocationHistoryRepository;
    private final ProofLogRepository proofLogRepository;

    @Override
    public List<AuditLogEntity> getAuditLogs(UUID auditorId) {
        ensureAuditor(auditorId);
        return auditLogRepository.findAllByOrderByCreatedAtDesc();
    }

    @Override
    public List<RevocationHistoryEntity> getRevocationHistory(UUID auditorId) {
        ensureAuditor(auditorId);
        return revocationHistoryRepository.findAllByOrderByRevokedAtDesc();
    }

    @Override
    public List<ProofLogEntity> getProofLogs(UUID auditorId) {
        ensureAuditor(auditorId);
        return proofLogRepository.findAllByOrderByVerifiedAtDesc();
    }

    private UserEntity ensureAuditor(UUID auditorId) {
        return userRepository.findByIdAndRole(auditorId, UserRole.AUDITOR)
                .orElseThrow(() -> new IllegalArgumentException("Auditor not found: " + auditorId));
    }
}
