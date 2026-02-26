package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.holder.AccessControlRequest;
import SSI.Wallet.Identity.dto.holder.CreateDocumentTypeRequest;
import SSI.Wallet.Identity.dto.holder.DocumentTypeResponse;
import SSI.Wallet.Identity.dto.holder.HolderCredentialAccessResponse;
import SSI.Wallet.Identity.dto.holder.HolderDocumentResponse;
import SSI.Wallet.Identity.dto.holder.HolderReviewRequestResponse;
import SSI.Wallet.Identity.dto.holder.IssuerEncryptionKeyResponse;
import SSI.Wallet.Identity.dto.holder.RespondReviewRequest;
import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRequest;
import SSI.Wallet.Identity.dto.holder.UploadDocumentRecipientKeyRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.CredentialKeyEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.DocumentReviewRequestEntity;
import SSI.Wallet.Identity.model.entity.DocumentTypeEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.DocumentReviewRequestStatus;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialKeyRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.DocumentKeyRepository;
import SSI.Wallet.Identity.repository.DocumentReviewRequestRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.DocumentTypeRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.HolderService;
import SSI.Wallet.Identity.service.VerifierService;
import SSI.Wallet.Identity.dto.verifier.ProofRequestSummaryResponse;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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
    private final CredentialKeyRepository credentialKeyRepository;
    private final DocumentKeyRepository documentKeyRepository;
    private final DocumentReviewRequestRepository documentReviewRequestRepository;
    private final DocumentTypeRepository documentTypeRepository;
    private final AuditLogRepository auditLogRepository;
    private final VerifierService verifierService;

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
        return credentialRepository.findByHolderId(holderId);
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
    @Transactional(readOnly = true)
    public List<IssuerEncryptionKeyResponse> getAvailableIssuers() {
        return userRepository.findByRoleAndEncryptionPublicKeyIsNotNullOrderByCreatedAtAsc(UserRole.ISSUER).stream()
                .filter(issuer -> !isBlank(issuer.getEncryptionPublicKey()))
                .map(issuer -> new IssuerEncryptionKeyResponse(
                        issuer.getId(),
                        issuer.getWalletAddress(),
                        issuer.getEncryptionPublicKey().trim()
                ))
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

        saveEncryptedKey(document, holder, request.encryptedKey().trim());
        Set<UUID> savedRecipientIds = new HashSet<>();
        savedRecipientIds.add(holder.getId());

        if (request.recipientKeys() != null) {
            for (UploadDocumentRecipientKeyRequest recipientKey : request.recipientKeys()) {
                UUID recipientId = recipientKey.recipientUserId();
                if (savedRecipientIds.contains(recipientId)) {
                    continue;
                }

                UserEntity recipient = userRepository.findByIdAndRole(recipientId, UserRole.ISSUER)
                        .orElseThrow(() -> new IllegalArgumentException(
                                "Recipient issuer not found: " + recipientId
                        ));

                saveEncryptedKey(document, recipient, recipientKey.encryptedKey().trim());
                savedRecipientIds.add(recipientId);
            }
        }

        createAuditLog(holder, "UPLOAD_DOCUMENT", "DOCUMENT", document.getId().toString());
        return toDocumentResponse(document);
    }

    @Override
    @Transactional(readOnly = true)
    public List<HolderReviewRequestResponse> getHolderReviewRequests(UUID holderId) {
        UserEntity holder = getHolderProfile(holderId);
        return documentReviewRequestRepository.findByHolderIdOrderByUpdatedAtDesc(holder.getId()).stream()
                .map(request -> toHolderReviewRequestResponse(request, holder.getId()))
                .toList();
    }

    @Override
    public HolderReviewRequestResponse respondReviewRequest(RespondReviewRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Review decision request is required.");
        }

        UserEntity holder = getHolderProfile(request.holderId());
        DocumentReviewRequestEntity reviewRequest = documentReviewRequestRepository
                .findByIdAndHolderId(request.requestId(), holder.getId())
                .orElseThrow(() -> new IllegalArgumentException("Review request not found: " + request.requestId()));

        if (!DocumentReviewRequestStatus.REQUESTED.equals(reviewRequest.getStatus())) {
            throw new IllegalArgumentException(
                    "Review request is not pending holder action: " + reviewRequest.getId()
            );
        }

        if (request.approved()) {
            if (isBlank(request.encryptedKeyForIssuer())) {
                throw new IllegalArgumentException("encryptedKeyForIssuer is required when approved=true.");
            }
            documentKeyRepository.save(
                    DocumentKeyEntity.builder()
                            .document(reviewRequest.getDocument())
                            .recipientUser(reviewRequest.getIssuer())
                            .encryptedKey(request.encryptedKeyForIssuer().trim())
                            .build()
            );
            reviewRequest.setStatus(DocumentReviewRequestStatus.HOLDER_APPROVED);
        } else {
            reviewRequest.setStatus(DocumentReviewRequestStatus.HOLDER_REJECTED);
        }

        if (!isBlank(request.note())) {
            reviewRequest.setHolderNote(request.note().trim());
        }

        DocumentReviewRequestEntity saved = documentReviewRequestRepository.save(reviewRequest);
        createAuditLog(holder, "DOCUMENT_REVIEW_RESPONSE", "DOCUMENT", saved.getDocument().getId().toString());
        return toHolderReviewRequestResponse(saved, holder.getId());
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
    @Transactional(readOnly = true)
    public List<ProofRequestSummaryResponse> getProofRequests(UUID holderId) {
        getHolderProfile(holderId);
        return verifierService.getHolderRequests(holderId);
    }

    @Override
    @Transactional(readOnly = true)
    public HolderCredentialAccessResponse getCredentialAccess(UUID holderId, String credentialId) {
        UserEntity holder = getHolderProfile(holderId);
        if (isBlank(credentialId)) {
            throw new IllegalArgumentException("credentialId is required.");
        }

        CredentialEntity credential = credentialRepository.findByCredentialId(credentialId.trim())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + credentialId));
        ensureHolderOwnsCredential(holder, credential);

        CredentialKeyEntity key = credentialKeyRepository
                .findTopByCredentialIdAndRecipientUserIdOrderByCreatedAtDesc(credential.getId(), holder.getId())
                .orElseThrow(() -> new IllegalArgumentException(
                        "Holder encrypted credential key not found for credential: " + credentialId
                ));

        return new HolderCredentialAccessResponse(
                credential.getCredentialId(),
                credential.getVcIpfsCid(),
                key.getEncryptedKey(),
                credential.getVcHash(),
                credential.getSignatureSuite(),
                credential.getRevoked(),
                credential.getIssuer() == null ? null : credential.getIssuer().getWalletAddress()
        );
    }

    @Override
    public ProofRequestSummaryResponse shareSelectiveProof(ShareProofRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Proof sharing request is required.");
        }
        UserEntity holder = getHolderProfile(request.holderId());
        ProofRequestSummaryResponse response = verifierService.processHolderProof(request);
        createAuditLog(holder, "SHARE_PROOF", "VERIFICATION_REQUEST", String.valueOf(request.requestId()));
        return response;
    }

    private void ensureHolderOwnsCredential(UserEntity holder, CredentialEntity credential) {
        UserEntity credentialHolder = credential.getHolder();
        if (credentialHolder == null && credential.getDocument() != null) {
            credentialHolder = credential.getDocument().getUser();
        }
        if (credentialHolder == null) {
            throw new IllegalArgumentException("Credential is not linked to a holder-owned document.");
        }
        if (!credentialHolder.getId().equals(holder.getId())) {
            throw new IllegalArgumentException("Holder does not own credential: " + credential.getCredentialId());
        }
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

    private HolderReviewRequestResponse toHolderReviewRequestResponse(
            DocumentReviewRequestEntity request,
            UUID holderId
    ) {
        String documentType = request.getDocument().getDocumentType() == null
                ? null
                : request.getDocument().getDocumentType().getName();
        String holderEncryptedKey = documentKeyRepository
                .findTopByDocumentIdAndRecipientUserIdOrderByCreatedAtDesc(request.getDocument().getId(), holderId)
                .map(DocumentKeyEntity::getEncryptedKey)
                .orElse(null);

        return new HolderReviewRequestResponse(
                request.getId(),
                request.getDocument().getId(),
                request.getDocument().getFileName(),
                documentType,
                request.getIssuer().getId(),
                request.getIssuer().getWalletAddress(),
                firstNonBlank(request.getIssuerEncryptionPublicKey(), request.getIssuer().getEncryptionPublicKey()),
                request.getStatus().name(),
                request.getIssuerNote(),
                request.getHolderNote(),
                holderEncryptedKey,
                request.getCreatedAt(),
                request.getUpdatedAt()
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
        if (request.recipientKeys() == null) {
            return;
        }
        for (UploadDocumentRecipientKeyRequest recipientKey : request.recipientKeys()) {
            if (recipientKey == null) {
                throw new IllegalArgumentException("recipientKeys contains an empty item.");
            }
            if (recipientKey.recipientUserId() == null) {
                throw new IllegalArgumentException("recipientUserId is required for each recipient key.");
            }
            if (isBlank(recipientKey.encryptedKey())) {
                throw new IllegalArgumentException(
                        "encryptedKey is required for recipient " + recipientKey.recipientUserId()
                );
            }
        }
    }

    private void saveEncryptedKey(DocumentEntity document, UserEntity recipient, String encryptedKey) {
        documentKeyRepository.save(
                DocumentKeyEntity.builder()
                        .document(document)
                        .recipientUser(recipient)
                        .encryptedKey(encryptedKey)
                        .build()
        );
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

    private String firstNonBlank(String first, String second) {
        if (!isBlank(first)) {
            return first.trim();
        }
        if (!isBlank(second)) {
            return second.trim();
        }
        return null;
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
