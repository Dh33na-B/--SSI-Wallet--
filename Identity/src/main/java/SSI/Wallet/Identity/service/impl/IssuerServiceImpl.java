package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.issuer.AnchorCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentAccessResponse;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentDecisionRequest;
import SSI.Wallet.Identity.dto.issuer.IssuerDocumentQueueItemResponse;
import SSI.Wallet.Identity.dto.issuer.IssuerReviewRequestResponse;
import SSI.Wallet.Identity.dto.issuer.IssueCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.RequestDocumentOpenRequest;
import SSI.Wallet.Identity.dto.issuer.RevokeCredentialRequest;
import SSI.Wallet.Identity.dto.issuer.VerifyDocumentRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.CredentialKeyEntity;
import SSI.Wallet.Identity.model.entity.DocumentEntity;
import SSI.Wallet.Identity.model.entity.DocumentKeyEntity;
import SSI.Wallet.Identity.model.entity.DocumentReviewRequestEntity;
import SSI.Wallet.Identity.model.entity.RevocationHistoryEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.DocumentReviewRequestStatus;
import SSI.Wallet.Identity.model.enums.DocumentStatus;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.CredentialKeyRepository;
import SSI.Wallet.Identity.repository.DocumentKeyRepository;
import SSI.Wallet.Identity.repository.DocumentReviewRequestRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.RevocationHistoryRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.IssuerService;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class IssuerServiceImpl implements IssuerService {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final DocumentReviewRequestRepository documentReviewRequestRepository;
    private final DocumentKeyRepository documentKeyRepository;
    private final CredentialRepository credentialRepository;
    private final CredentialKeyRepository credentialKeyRepository;
    private final RevocationHistoryRepository revocationHistoryRepository;
    private final AuditLogRepository auditLogRepository;
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Value("${pinata.jwt:}")
    private String pinataJwt;

    @Value("${pinata.api.key:}")
    private String pinataApiKey;

    @Value("${pinata.api.secret:}")
    private String pinataApiSecret;

    @Override
    @Transactional(readOnly = true)
    public List<IssuerDocumentQueueItemResponse> getSubmittedDocuments(UUID issuerId) {
        UserEntity issuer = getIssuer(issuerId);
        return documentRepository.findAllByOrderByUploadedAtDesc().stream()
                .map(document -> toIssuerDocumentQueueItem(document, issuer.getId()))
                .toList();
    }

    @Override
    public IssuerReviewRequestResponse requestDocumentOpen(RequestDocumentOpenRequest request) {
        validateOpenRequest(request);

        UserEntity issuer = getIssuer(request.issuerId());
        DocumentEntity document = getDocumentOrThrow(request.documentId());
        if (!DocumentStatus.PENDING.equals(document.getStatus())) {
            throw new IllegalArgumentException(
                    "Only PENDING documents can be opened. Current status: " + document.getStatus().name()
            );
        }
        UserEntity holder = document.getUser();
        String issuerEncryptionPublicKey = firstNonBlank(
                request.issuerEncryptionPublicKey(),
                issuer.getEncryptionPublicKey()
        );
        if (isBlank(issuerEncryptionPublicKey)) {
            throw new IllegalArgumentException("Issuer encryption public key is required to request document access.");
        }

        DocumentReviewRequestEntity latest = documentReviewRequestRepository
                .findTopByDocumentIdAndIssuerIdOrderByCreatedAtDesc(document.getId(), issuer.getId())
                .orElse(null);

        if (latest != null && isPendingOrApproved(latest.getStatus())) {
            if (isBlank(latest.getIssuerEncryptionPublicKey())) {
                latest.setIssuerEncryptionPublicKey(issuerEncryptionPublicKey.trim());
                latest = documentReviewRequestRepository.save(latest);
            }
            return toIssuerReviewRequestResponse(latest);
        }

        DocumentReviewRequestEntity created = documentReviewRequestRepository.save(
                DocumentReviewRequestEntity.builder()
                        .document(document)
                        .holder(holder)
                        .issuer(issuer)
                        .issuerEncryptionPublicKey(issuerEncryptionPublicKey.trim())
                        .status(DocumentReviewRequestStatus.REQUESTED)
                        .build()
        );

        createAuditLog(issuer, "REQUEST_DOCUMENT_OPEN", "DOCUMENT", document.getId().toString());
        return toIssuerReviewRequestResponse(created);
    }

    @Override
    @Transactional(readOnly = true)
    public IssuerDocumentAccessResponse getDocumentAccess(UUID issuerId, UUID documentId) {
        UserEntity issuer = getIssuer(issuerId);
        DocumentEntity document = getDocumentOrThrow(documentId);

        DocumentReviewRequestEntity reviewRequest = documentReviewRequestRepository
                .findTopByDocumentIdAndIssuerIdOrderByCreatedAtDesc(document.getId(), issuer.getId())
                .orElse(null);

        String encryptedKey = findEncryptedDocumentKey(document.getId(), issuer.getId());
        String reviewStatus = reviewRequest == null
                ? (encryptedKey == null ? "NO_ACCESS_REQUESTED" : "DIRECT_ACCESS_READY")
                : reviewRequest.getStatus().name();

        return new IssuerDocumentAccessResponse(
                document.getId(),
                document.getUser().getId(),
                document.getUser().getWalletAddress(),
                document.getUser().getEncryptionPublicKey(),
                document.getFileName(),
                document.getDocumentType() == null ? null : document.getDocumentType().getName(),
                document.getIpfsCid(),
                document.getEncryptionIv(),
                encryptedKey,
                reviewRequest == null ? null : reviewRequest.getId(),
                reviewStatus
        );
    }

    @Override
    public IssuerDocumentQueueItemResponse decideDocument(IssuerDocumentDecisionRequest request) {
        validateDecisionRequest(request);

        UserEntity issuer = getIssuer(request.issuerId());
        DocumentEntity document = getDocumentOrThrow(request.documentId());

        DocumentReviewRequestEntity reviewRequest = documentReviewRequestRepository
                .findTopByDocumentIdAndIssuerIdOrderByCreatedAtDesc(document.getId(), issuer.getId())
                .orElse(null);

        if (reviewRequest != null
                && (DocumentReviewRequestStatus.ISSUER_ACCEPTED.equals(reviewRequest.getStatus())
                || DocumentReviewRequestStatus.ISSUER_REJECTED_REUPLOAD_REQUIRED.equals(reviewRequest.getStatus()))) {
            throw new IllegalArgumentException("Review request is already finalized for this document.");
        }

        boolean hasIssuerEncryptedKey = findEncryptedDocumentKey(document.getId(), issuer.getId()) != null;

        if (request.approved()) {
            boolean holderApprovedReview = reviewRequest != null
                    && DocumentReviewRequestStatus.HOLDER_APPROVED.equals(reviewRequest.getStatus());
            if (!holderApprovedReview && !hasIssuerEncryptedKey) {
                throw new IllegalArgumentException(
                        "Issuer encrypted key is not available. Request holder access before accepting verification."
                );
            }
            document.setStatus(DocumentStatus.VERIFIED);
            if (reviewRequest == null) {
                reviewRequest = createDecisionReviewRecord(
                        document,
                        issuer,
                        DocumentReviewRequestStatus.ISSUER_ACCEPTED
                );
            } else {
                reviewRequest.setStatus(DocumentReviewRequestStatus.ISSUER_ACCEPTED);
            }
        } else {
            document.setStatus(DocumentStatus.REJECTED);
            if (reviewRequest == null) {
                reviewRequest = createDecisionReviewRecord(
                        document,
                        issuer,
                        DocumentReviewRequestStatus.ISSUER_REJECTED_REUPLOAD_REQUIRED
                );
            } else {
                reviewRequest.setStatus(DocumentReviewRequestStatus.ISSUER_REJECTED_REUPLOAD_REQUIRED);
            }

            if (request.removePreviousCid()) {
                unpinCidIfConfigured(document.getIpfsCid());
                document.setIpfsCid("REMOVED");
            }
        }

        if (!isBlank(request.reason())) {
            reviewRequest.setIssuerNote(request.reason().trim());
        }

        documentRepository.save(document);
        documentReviewRequestRepository.save(reviewRequest);
        createAuditLog(issuer, "DECIDE_DOCUMENT", "DOCUMENT", document.getId().toString());

        return toIssuerDocumentQueueItem(document, issuer.getId());
    }

    @Override
    public DocumentEntity verifyDocument(VerifyDocumentRequest request) {
        decideDocument(
                new IssuerDocumentDecisionRequest(
                        request.issuerId(),
                        request.documentId(),
                        request.approved(),
                        null,
                        !request.approved()
                )
        );
        return getDocumentOrThrow(request.documentId());
    }

    @Override
    @Transactional(readOnly = true)
    public CredentialEntity getDocumentCredential(UUID issuerId, UUID documentId) {
        UserEntity issuer = getIssuer(issuerId);
        CredentialEntity credential = credentialRepository.findTopByDocumentIdOrderByIssuedAtDesc(documentId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Credential not found for document: " + documentId
                ));
        if (credential.getIssuer() != null && !issuer.getId().equals(credential.getIssuer().getId())) {
            throw new IllegalArgumentException("Issuer does not own credential for document: " + documentId);
        }
        return credential;
    }

    @Override
    @Transactional(readOnly = true)
    public List<CredentialEntity> getIssuedCredentials(UUID issuerId) {
        UserEntity issuer = getIssuer(issuerId);
        return credentialRepository.findByIssuerIdOrderByIssuedAtDesc(issuer.getId());
    }

    @Override
    public CredentialEntity issueCredential(IssueCredentialRequest request) {
        validateIssueCredentialRequest(request);
        UserEntity issuer = getIssuer(request.issuerId());
        DocumentEntity document = documentRepository.findById(request.documentId())
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + request.documentId()));
        UserEntity holder = document.getUser();

        if (!DocumentStatus.VERIFIED.equals(document.getStatus())) {
            throw new IllegalArgumentException("Credential can be issued only for VERIFIED documents.");
        }
        if (credentialRepository.existsByDocumentId(document.getId())) {
            throw new IllegalArgumentException("A credential is already issued for this document.");
        }

        CredentialEntity created = credentialRepository.save(
                CredentialEntity.builder()
                        .document(document)
                        .issuer(issuer)
                        .holder(holder)
                        .credentialId(request.credentialId())
                        .vcIpfsCid(request.vcIpfsCid().trim())
                        .vcHash(request.vcHash().trim())
                        .signatureSuite(request.signatureSuite().trim())
                        .blockchainTxHash(request.blockchainTxHash().trim())
                        .expiresAt(request.expiresAt())
                        .build()
        );

        credentialKeyRepository.save(
                CredentialKeyEntity.builder()
                        .credential(created)
                        .recipientUser(holder)
                        .encryptedKey(request.holderEncryptedKey().trim())
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

    private IssuerDocumentQueueItemResponse toIssuerDocumentQueueItem(DocumentEntity document, UUID issuerId) {
        DocumentReviewRequestEntity latest = documentReviewRequestRepository
                .findTopByDocumentIdAndIssuerIdOrderByCreatedAtDesc(document.getId(), issuerId)
                .orElse(null);

        return new IssuerDocumentQueueItemResponse(
                document.getId(),
                document.getUser().getId(),
                document.getUser().getWalletAddress(),
                document.getFileName(),
                document.getDocumentType() == null ? null : document.getDocumentType().getName(),
                document.getStatus().name(),
                document.getUploadedAt(),
                latest == null ? null : latest.getId(),
                latest == null ? null : latest.getStatus().name()
        );
    }

    private IssuerReviewRequestResponse toIssuerReviewRequestResponse(DocumentReviewRequestEntity request) {
        return new IssuerReviewRequestResponse(
                request.getId(),
                request.getDocument().getId(),
                request.getStatus().name(),
                request.getIssuerNote(),
                request.getHolderNote(),
                request.getCreatedAt(),
                request.getUpdatedAt()
        );
    }

    private DocumentEntity getDocumentOrThrow(UUID documentId) {
        return documentRepository.findById(documentId)
                .orElseThrow(() -> new IllegalArgumentException("Document not found: " + documentId));
    }

    private String findEncryptedDocumentKey(UUID documentId, UUID recipientUserId) {
        return documentKeyRepository
                .findTopByDocumentIdAndRecipientUserIdOrderByCreatedAtDesc(documentId, recipientUserId)
                .map(DocumentKeyEntity::getEncryptedKey)
                .orElse(null);
    }

    private DocumentReviewRequestEntity createDecisionReviewRecord(
            DocumentEntity document,
            UserEntity issuer,
            DocumentReviewRequestStatus status
    ) {
        return DocumentReviewRequestEntity.builder()
                .document(document)
                .holder(document.getUser())
                .issuer(issuer)
                .issuerEncryptionPublicKey(issuer.getEncryptionPublicKey())
                .status(status)
                .build();
    }

    private boolean isPendingOrApproved(DocumentReviewRequestStatus status) {
        return DocumentReviewRequestStatus.REQUESTED.equals(status)
                || DocumentReviewRequestStatus.HOLDER_APPROVED.equals(status);
    }

    private void validateOpenRequest(RequestDocumentOpenRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Open request is required.");
        }
        if (request.issuerId() == null) {
            throw new IllegalArgumentException("issuerId is required.");
        }
        if (request.documentId() == null) {
            throw new IllegalArgumentException("documentId is required.");
        }
    }

    private void validateDecisionRequest(IssuerDocumentDecisionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Decision request is required.");
        }
        if (request.issuerId() == null) {
            throw new IllegalArgumentException("issuerId is required.");
        }
        if (request.documentId() == null) {
            throw new IllegalArgumentException("documentId is required.");
        }
    }

    private void validateIssueCredentialRequest(IssueCredentialRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Issue credential request is required.");
        }
        if (request.issuerId() == null) {
            throw new IllegalArgumentException("issuerId is required.");
        }
        if (request.documentId() == null) {
            throw new IllegalArgumentException("documentId is required.");
        }
        if (isBlank(request.credentialId())) {
            throw new IllegalArgumentException("credentialId is required.");
        }
        if (isBlank(request.vcIpfsCid())) {
            throw new IllegalArgumentException("vcIpfsCid is required.");
        }
        if (isBlank(request.vcHash())) {
            throw new IllegalArgumentException("vcHash is required.");
        }
        if (isBlank(request.signatureSuite())) {
            throw new IllegalArgumentException("signatureSuite is required.");
        }
        if (!"BbsBlsSignature2020".equalsIgnoreCase(request.signatureSuite().trim())) {
            throw new IllegalArgumentException("Only BbsBlsSignature2020 signatureSuite is supported.");
        }
        if (isBlank(request.blockchainTxHash())) {
            throw new IllegalArgumentException("blockchainTxHash is required.");
        }
        if (isBlank(request.holderEncryptedKey())) {
            throw new IllegalArgumentException("holderEncryptedKey is required.");
        }
    }

    private void unpinCidIfConfigured(String cid) {
        if (isBlank(cid) || "REMOVED".equalsIgnoreCase(cid)) {
            return;
        }
        if (isBlank(pinataJwt) && (isBlank(pinataApiKey) || isBlank(pinataApiSecret))) {
            return;
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("https://api.pinata.cloud/pinning/unpin/" + cid))
                .DELETE();

        if (!isBlank(pinataJwt)) {
            builder.header("Authorization", "Bearer " + pinataJwt.trim());
        } else {
            builder.header("pinata_api_key", pinataApiKey.trim());
            builder.header("pinata_secret_api_key", pinataApiSecret.trim());
        }

        try {
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300 && response.statusCode() != 404) {
                throw new IllegalArgumentException(
                        "Pinata unpin failed for CID " + cid + " with status " + response.statusCode()
                );
            }
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalArgumentException("Pinata unpin failed for CID " + cid);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private String firstNonBlank(String first, String second) {
        if (!isBlank(first)) {
            return first;
        }
        return second;
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
