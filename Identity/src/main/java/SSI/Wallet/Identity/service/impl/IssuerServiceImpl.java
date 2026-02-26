package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.issuer.AnchorCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.IssueCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.RevokeCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.VerifyDocumentRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.DocumentStatus;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.RevocationHistoryRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.IssuerService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class IssuerServiceImpl implements IssuerService {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final CredentialRepository credentialRepository;
    private final RevocationHistoryRepository revocationHistoryRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    public DocumentEntity verifyDocument(VerifyDocumentRequest request) {
        UserEntity issuer = getIssuer(request.issuerId());
        DocumentEntity document = documentRepository.findById(request.documentId())
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + request.documentId()));

        document.setStatus(request.approved() ? DocumentStatus.VERIFIED : DocumentStatus.REJECTED);
        DocumentEntity saved = documentRepository.save(document);

        createAuditLog(issuer, "VERIFY_DOCUMENT", "DOCUMENT", request.documentId().toString());
        return saved;
    }

    @Override
    public CredentialEntity issueCredential(IssueCredentialRequest request) {
        UserEntity issuer = getIssuer(request.issuerId());
        DocumentEntity document = documentRepository.findById(request.documentId())
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + request.documentId()));

        if (!DocumentStatus.VERIFIED.equals(document.getStatus())) {
            throw new IllegalArgumentException("Credential can be issued only for VERIFIED documents.");
        }

        CredentialEntity created = credentialRepository.save(
                CredentialEntity.builder()
                        .document(document)
                        .issuer(issuer)
                        .credentialId(request.credentialId())
                        .vcIpfsCid(request.vcIpfsCid())
                        .vcHash(request.vcHash())
                        .expiresAt(request.expiresAt())
                        .build()
        );

        createAuditLog(issuer, "ISSUE_CREDENTIAL", "CREDENTIAL", request.credentialId());
        return created;
    }

    @Override
    public CredentialEntity anchorCredentialHash(AnchorCredentialRequest request) {
        UserEntity issuer = getIssuer(request.issuerId());
        CredentialEntity credential = credentialRepository.findByCredentialId(request.credentialId())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + request.credentialId()));

        if (credential.getIssuer() != null && !issuer.getId().equals(credential.getIssuer().getId())) {
            throw new IllegalArgumentException("Issuer does not own credential: " + request.credentialId());
        }

        credential.setBlockchainTxHash(request.blockchainTxHash());
        CredentialEntity updated = credentialRepository.save(credential);

        createAuditLog(issuer, "ANCHOR_HASH", "CREDENTIAL", request.credentialId());
        return updated;
    }

    @Override
    public RevocationHistoryEntity revokeCredential(RevokeCredentialRequest request) {
        UserEntity issuer = getIssuer(request.issuerId());
        CredentialEntity credential = credentialRepository.findByCredentialId(request.credentialId())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + request.credentialId()));

        if (credential.getIssuer() != null && !issuer.getId().equals(credential.getIssuer().getId())) {
            throw new IllegalArgumentException("Issuer does not own credential: " + request.credentialId());
        }

        credential.setRevoked(Boolean.TRUE);
        credentialRepository.save(credential);

        RevocationHistoryEntity history = revocationHistoryRepository.save(
                RevocationHistoryEntity.builder()
                        .credential(credential)
                        .revokedBy(issuer)
                        .reason(request.reason())
                        .build()
        );

        createAuditLog(issuer, "REVOKE_CREDENTIAL", "CREDENTIAL", request.credentialId());
        return history;
    }

    private UserEntity getIssuer(java.util.UUID issuerId) {
        return userRepository.findByIdAndRole(issuerId, UserRole.ISSUER)
                .orElseThrow(() -> new IllegalArgumentException("Issuer not found: " + issuerId));
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
