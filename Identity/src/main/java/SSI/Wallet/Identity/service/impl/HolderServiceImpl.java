package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.CreateDocumentTypeRequest;
import SSI.Wallet.Identity.dto.holder.DocumentTypeResponse;
import SSI.Wallet.Identity.dto.holder.HolderDocumentResponse;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.DocumentTypeEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.DocumentKeyRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.DocumentTypeRepository;
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
    private final DocumentTypeRepository documentTypeRepository;
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
    @Transactional(readOnly = true)
    public List<HolderDocumentResponse> getHolderDocuments(UUID holderId) {
        getHolderProfile(holderId);
        return documentRepository.findByUserIdOrderByUploadedAtDesc(holderId).stream()
                .map(this::toDocumentResponse)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<DocumentTypeResponse> getDocumentTypes() {
        return documentTypeRepository.findAllByOrderByNameAsc().stream()
                .map(type -> new DocumentTypeResponse(type.getId(), type.getName()))
                .toList();
    }

    @Override
    public DocumentTypeResponse createDocumentType(CreateDocumentTypeRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Document type request is required.");
        }
        if (isBlank(request.name())) {
            throw new IllegalArgumentException("Document type name is required.");
        }
        UserEntity holder = getHolderProfile(request.holderId());
        DocumentTypeEntity type = findOrCreateDocumentType(request.name(), holder);
        return new DocumentTypeResponse(type.getId(), type.getName());
    }

    @Override
    public HolderDocumentResponse uploadEncryptedDocument(UploadDocumentRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Upload request is required.");
        }
        UserEntity holder = getHolderProfile(request.holderId());
        validateUploadRequest(request);

        DocumentTypeEntity type = resolveDocumentType(request, holder);

        DocumentEntity document = documentRepository.save(
                DocumentEntity.builder()
                        .user(holder)
                        .documentType(type)
                        .fileName(request.fileName().trim())
                        .ipfsCid(request.ipfsCid().trim())
                        .encryptionIv(request.encryptionIv().trim())
                        .build()
        );

        documentKeyRepository.save(
                DocumentKeyEntity.builder()
                        .document(document)
                        .recipientUser(holder)
                        .encryptedKey(request.encryptedKey().trim())
                        .build()
        );

        createAuditLog(holder, "UPLOAD_DOCUMENT", "DOCUMENT", document.getId().toString());
        return toDocumentResponse(document);
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

    private DocumentTypeEntity resolveDocumentType(UploadDocumentRequest request, UserEntity holder) {
        if (request.documentTypeId() != null) {
            return documentTypeRepository.findById(request.documentTypeId())
                    .orElseThrow(() -> new IllegalArgumentException(
                            "Document type not found: " + request.documentTypeId()
                    ));
        }
        if (!isBlank(request.newDocumentTypeName())) {
            return findOrCreateDocumentType(request.newDocumentTypeName(), holder);
        }
        throw new IllegalArgumentException("documentTypeId or newDocumentTypeName is required.");
    }

    private DocumentTypeEntity findOrCreateDocumentType(String rawName, UserEntity creator) {
        String normalized = normalizeTypeName(rawName);
        return documentTypeRepository.findByNameIgnoreCase(normalized)
                .orElseGet(() -> documentTypeRepository.save(
                        DocumentTypeEntity.builder()
                                .name(normalized)
                                .createdBy(creator)
                                .build()
                ));
    }

    private HolderDocumentResponse toDocumentResponse(DocumentEntity document) {
        String documentType = document.getDocumentType() == null ? null : document.getDocumentType().getName();
        return new HolderDocumentResponse(
                document.getId(),
                document.getFileName(),
                documentType,
                document.getIpfsCid(),
                document.getStatus().name(),
                document.getUploadedAt()
        );
    }

    private void validateUploadRequest(UploadDocumentRequest request) {
        if (isBlank(request.fileName())) {
            throw new IllegalArgumentException("fileName is required.");
        }
        if (isBlank(request.ipfsCid())) {
            throw new IllegalArgumentException("ipfsCid is required.");
        }
        if (isBlank(request.encryptionIv())) {
            throw new IllegalArgumentException("encryptionIv is required.");
        }
        if (isBlank(request.encryptedKey())) {
            throw new IllegalArgumentException("encryptedKey is required.");
        }
    }

    private String normalizeTypeName(String rawName) {
        String trimmed = rawName == null ? "" : rawName.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Document type name is required.");
        }
        if (trimmed.length() > 100) {
            throw new IllegalArgumentException("Document type name is too long.");
        }
        return trimmed;
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
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
