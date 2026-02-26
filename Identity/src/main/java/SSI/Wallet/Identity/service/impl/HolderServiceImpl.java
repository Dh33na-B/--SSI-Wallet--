package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.DocumentKeyRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.HolderService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class HolderServiceImpl implements HolderService {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final CredentialRepository credentialRepository;
    private final DocumentKeyRepository documentKeyRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    @Transactional(readOnly = true)
    public UserEntity getHolderProfile(UUID holderId) {
        return userRepository.findByIdAndRole(holderId, UserRole.USER)
                .orElseThrow(() -> new IllegalArgumentException("Holder not found: " + holderId));
    }

    @Override
    @Transactional(readOnly = true)
    public List<CredentialEntity> getHolderCredentials(UUID holderId) {
        getHolderProfile(holderId);
        return credentialRepository.findByDocumentUserId(holderId);
    }

    @Override
    public DocumentKeyEntity grantDocumentAccess(AccessControlRequest request) {
        UserEntity holder = getHolderProfile(request.holderId());
        DocumentEntity document = documentRepository.findById(request.documentId())
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + request.documentId()));

        if (!document.getUser().getId().equals(holder.getId())) {
            throw new IllegalArgumentException("Holder does not own document: " + request.documentId());
        }

        UserEntity recipient = userRepository.findById(request.recipientUserId())
                .orElseThrow(() -> new IllegalArgumentException("Recipient user not found: " + request.recipientUserId()));

        DocumentKeyEntity created = documentKeyRepository.save(
                DocumentKeyEntity.builder()
                        .document(document)
                        .recipientUser(recipient)
                        .encryptedKey(request.encryptedKey())
                        .build()
        );

        createAuditLog(holder, "GRANT_ACCESS", "DOCUMENT", request.documentId().toString());
        return created;
    }

    @Override
    public String shareSelectiveProof(ShareProofRequest request) {
        UserEntity holder = getHolderProfile(request.holderId());

        CredentialEntity credential = credentialRepository.findByCredentialId(request.credentialId())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + request.credentialId()));

        if (credential.getDocument() == null || credential.getDocument().getUser() == null) {
            throw new IllegalArgumentException("Credential is not linked to a holder-owned document.");
        }

        if (!credential.getDocument().getUser().getId().equals(holder.getId())) {
            throw new IllegalArgumentException("Holder does not own credential: " + request.credentialId());
        }

        createAuditLog(holder, "SHARE_PROOF", "CREDENTIAL", request.credentialId());
        return "Selective proof template generated for verifier " + request.verifierId()
                + " with fields: " + request.requestedFields();
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
