package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.ProofLogRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.VerifierService;
import java.time.LocalDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class VerifierServiceImpl implements VerifierService {

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final ProofLogRepository proofLogRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    public String requestProof(RequestProofRequest request) {
        UserEntity verifier = getVerifier(request.verifierId());
        createAuditLog(verifier, "REQUEST_PROOF", "CREDENTIAL", request.credentialId());
        return "Proof request template sent for credential " + request.credentialId()
                + " to holder " + request.holderId()
                + " requesting fields: " + request.requestedFields();
    }

    @Override
    public ProofLogEntity verifyCredential(VerifyCredentialRequest request) {
        UserEntity verifier = getVerifier(request.verifierId());
        CredentialEntity credential = credentialRepository.findByCredentialId(request.credentialId())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + request.credentialId()));

        boolean isNotRevoked = !Boolean.TRUE.equals(credential.getRevoked());
        boolean isNotExpired = credential.getExpiresAt() == null || credential.getExpiresAt().isAfter(LocalDateTime.now());
        boolean verified = isNotRevoked && isNotExpired;

        ProofLogEntity log = proofLogRepository.save(
                ProofLogEntity.builder()
                        .credential(credential)
                        .verifier(verifier)
                        .verificationStatus(verified)
                        .build()
        );

        createAuditLog(verifier, "VERIFY_CREDENTIAL", "CREDENTIAL", request.credentialId());
        return log;
    }

    @Override
    public ProofLogEntity submitDecision(VerificationDecisionRequest request) {
        UserEntity verifier = getVerifier(request.verifierId());
        CredentialEntity credential = credentialRepository.findByCredentialId(request.credentialId())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + request.credentialId()));

        ProofLogEntity log = proofLogRepository.save(
                ProofLogEntity.builder()
                        .credential(credential)
                        .verifier(verifier)
                        .verificationStatus(request.accepted())
                        .build()
        );

        createAuditLog(verifier, "DECISION_" + (request.accepted() ? "ACCEPT" : "REJECT"), "CREDENTIAL",
                request.credentialId());
        return log;
    }

    private UserEntity getVerifier(java.util.UUID verifierId) {
        return userRepository.findByIdAndRole(verifierId, UserRole.VERIFIER)
                .orElseThrow(() -> new IllegalArgumentException("Verifier not found: " + verifierId));
    }

    private void createAuditLog(UserEntity actor, String actionType, String entityType, String entityId) {
        auditLogRepository.save(
                AuditLogEntity.builder()
                        .user(actor)
                        .actionType(actionType)
                        .entityType(entityType)
                        .entityId(entityId)
                        .build()
        );
    }
}
