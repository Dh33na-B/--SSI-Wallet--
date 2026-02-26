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
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.crypto.Hash;

@Service
@RequiredArgsConstructor
@Transactional
public class IssuerServiceImpl implements IssuerService {

    private static final Pattern TX_HASH_PATTERN = Pattern.compile("0x[a-fA-F0-9]{64}");

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final DocumentReviewRequestRepository documentReviewRequestRepository;
    private final DocumentKeyRepository documentKeyRepository;
    private final CredentialRepository credentialRepository;
    private final CredentialKeyRepository credentialKeyRepository;
    private final RevocationHistoryRepository revocationHistoryRepository;
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Value("${pinata.jwt:}")
    private String pinataJwt;

    @Value("${pinata.api.key:}")
    private String pinataApiKey;

    @Value("${pinata.api.secret:}")
    private String pinataApiSecret;

    @Value("${bbs.signer.base-url:http://localhost:8085}")
    private String bbsSignerBaseUrl;

    @Value("${bbs.signer.auth-token:}")
    private String bbsSignerAuthToken;

    @Value("${bbs.signer.verification-method-suffix:#bbs-key-1}")
    private String bbsVerificationMethodSuffix;

    @Value("${bbs.signer.proof-purpose:assertionMethod}")
    private String bbsProofPurpose;

    @Value("${hardhat.anchor.command:}")
    private String hardhatAnchorCommand;

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
        if (isBlank(holder.getEncryptionPublicKey())) {
            throw new IllegalArgumentException("Holder encryption public key is missing.");
        }

        try {
            Map<String, Object> unsignedVc = buildUnsignedVc(request, issuer, holder);
            BbsSignResult bbsSigned = signCredentialWithBbsService(unsignedVc, issuer);
            String signedVcJson = objectMapper.writeValueAsString(bbsSigned.signedCredential());

            String vcHash = Hash.sha3String(signedVcJson);
            String blockchainTxHash = anchorCredentialHashWithHardhat(request.credentialId().trim(), vcHash);

            EncryptedPayload encryptedPayload = encryptSignedCredential(signedVcJson);
            String holderEncryptedKey = wrapSymmetricKeyForHolder(
                    holder.getEncryptionPublicKey().trim(),
                    encryptedPayload.keyBase64()
            );
            String vcIpfsCid = uploadEncryptedVcToPinata(encryptedPayload.blob(), request.credentialId().trim());

            CredentialEntity created = credentialRepository.save(
                    CredentialEntity.builder()
                            .document(document)
                            .issuer(issuer)
                            .holder(holder)
                            .credentialId(request.credentialId().trim())
                            .vcIpfsCid(vcIpfsCid)
                            .vcHash(vcHash)
                            .signatureSuite(bbsSigned.signatureSuite())
                            .blockchainTxHash(blockchainTxHash)
                            .expiresAt(request.expiresAt())
                            .build()
            );

            credentialKeyRepository.save(
                    CredentialKeyEntity.builder()
                            .credential(created)
                            .recipientUser(holder)
                            .encryptedKey(holderEncryptedKey)
                            .build()
            );

            createAuditLog(issuer, "ISSUE_CREDENTIAL", "CREDENTIAL", request.credentialId().trim());
            return created;
        } catch (IOException ex) {
            throw new IllegalArgumentException("Failed to serialize VC for signing.", ex);
        }
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

    private Map<String, Object> buildUnsignedVc(
            IssueCredentialRequest request,
            UserEntity issuer,
            UserEntity holder
    ) {
        Map<String, Object> credentialSubject = new LinkedHashMap<>();
        credentialSubject.put("id", holder.getWalletAddress());

        for (Map.Entry<String, Object> entry : request.claims().entrySet()) {
            if (!"id".equals(entry.getKey()) && entry.getValue() != null) {
                credentialSubject.put(entry.getKey(), entry.getValue());
            }
        }

        LocalDateTime nowUtc = LocalDateTime.now(ZoneOffset.UTC);
        String issuanceDate = nowUtc.atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        Map<String, Object> unsignedVc = new LinkedHashMap<>();
        unsignedVc.put("@context", List.of("https://www.w3.org/2018/credentials/v1"));
        unsignedVc.put("id", request.credentialId().trim());
        unsignedVc.put("type", List.of("VerifiableCredential", request.vcSchema().trim()));
        unsignedVc.put("issuer", "did:ethr:" + issuer.getWalletAddress());
        unsignedVc.put("issuanceDate", issuanceDate);
        if (request.expiresAt() != null) {
            unsignedVc.put(
                    "expirationDate",
                    request.expiresAt().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME)
            );
        }
        unsignedVc.put("credentialSubject", credentialSubject);
        return unsignedVc;
    }

    private BbsSignResult signCredentialWithBbsService(Map<String, Object> unsignedVc, UserEntity issuer) {
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("credential", unsignedVc);
        requestBody.put("proofPurpose", bbsProofPurpose);
        requestBody.put(
                "verificationMethod",
                "did:ethr:" + issuer.getWalletAddress() + firstNonBlank(bbsVerificationMethodSuffix, "#bbs-key-1")
        );

        Map<String, Object> response = postJsonToSigner("/v1/credentials/sign", requestBody, "BBS signer call failed.");
        Object signedCredentialRaw = response.get("signedCredential");
        if (!(signedCredentialRaw instanceof Map<?, ?> signedCredentialMapRaw)) {
            throw new IllegalArgumentException("Signer response missing signedCredential.");
        }
        Map<String, Object> signedCredential = objectMapper.convertValue(
                signedCredentialMapRaw,
                new TypeReference<Map<String, Object>>() {
                }
        );

        String signatureSuite = String.valueOf(response.get("signatureSuite"));
        if (isBlank(signatureSuite)) {
            signatureSuite = "BbsBlsSignature2020";
        }
        return new BbsSignResult(signedCredential, signatureSuite.trim());
    }

    private String wrapSymmetricKeyForHolder(String holderPublicKeyBase64, String keyBase64) {
        Map<String, Object> requestBody = new LinkedHashMap<>();
        requestBody.put("recipientPublicKeyBase64", holderPublicKeyBase64);
        // MetaMask eth_decrypt returns UTF-8 text, so wrap the base64 text of K_vc (not raw key bytes).
        String payloadTextAsBase64 = Base64.getEncoder().encodeToString(
                keyBase64.getBytes(StandardCharsets.UTF_8)
        );
        requestBody.put("payloadBase64", payloadTextAsBase64);

        Map<String, Object> response = postJsonToSigner("/v1/keys/wrap", requestBody, "Failed to wrap VC key for holder.");
        String envelopeHex = response.get("envelopeHex") == null ? "" : String.valueOf(response.get("envelopeHex"));
        if (!isBlank(envelopeHex)) {
            return envelopeHex.trim();
        }
        String envelopeJson = response.get("envelopeJson") == null ? "" : String.valueOf(response.get("envelopeJson"));
        if (!isBlank(envelopeJson)) {
            return envelopeJson.trim();
        }
        throw new IllegalArgumentException("Signer wrap response missing envelope.");
    }

    private Map<String, Object> postJsonToSigner(String path, Map<String, Object> payload, String fallbackMessage) {
        try {
            String requestJson = objectMapper.writeValueAsString(payload);
            String baseUrl = firstNonBlank(bbsSignerBaseUrl, "http://localhost:8085");
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestJson, StandardCharsets.UTF_8));
            if (!isBlank(bbsSignerAuthToken)) {
                builder.header("Authorization", "Bearer " + bbsSignerAuthToken.trim());
            }

            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                String apiMessage = readApiMessage(response.body());
                throw new IllegalArgumentException(firstNonBlank(apiMessage, fallbackMessage));
            }
            Map<String, Object> parsed = objectMapper.readValue(
                    response.body(),
                    new TypeReference<Map<String, Object>>() {
                    }
            );
            if (parsed == null) {
                throw new IllegalArgumentException(fallbackMessage);
            }
            return parsed;
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalArgumentException(fallbackMessage, ex);
        }
    }

    private String anchorCredentialHashWithHardhat(String credentialId, String vcHash) {
        java.io.File hardhatDir = resolveHardhatProjectDirectory();

        List<String> commands = new ArrayList<>();
        if (!isBlank(hardhatAnchorCommand)) {
            commands.add(hardhatAnchorCommand.trim());
        }
        String fallbackCommand = defaultHardhatAnchorCommand();
        if (!commands.contains(fallbackCommand)) {
            commands.add(fallbackCommand);
        }

        String lastError = null;
        for (String command : commands) {
            try {
                return runHardhatAnchorCommand(command, credentialId, vcHash, hardhatDir);
            } catch (IllegalArgumentException ex) {
                lastError = ex.getMessage();
            }
        }
        throw new IllegalArgumentException(
                "Hardhat anchor command failed. " + firstNonBlank(lastError, "No executable hardhat command found.")
        );
    }

    private String runHardhatAnchorCommand(
            String command,
            String credentialId,
            String vcHash,
            java.io.File hardhatDir
    ) {
        ProcessBuilder builder = buildShellCommand(command.trim());
        builder.directory(hardhatDir);
        builder.environment().put("VC_HASH", vcHash);
        builder.environment().put("CREDENTIAL_ID", credentialId);

        try {
            Process process = builder.start();
            boolean finished = process.waitFor(90, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalArgumentException("Hardhat anchor command timed out.");
            }

            String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                throw new IllegalArgumentException(
                        "Hardhat command `" + command + "` failed. " + firstNonBlank(stderr, stdout)
                );
            }

            String txHash = extractTxHash(stdout + "\n" + stderr);
            if (isBlank(txHash)) {
                throw new IllegalArgumentException("Hardhat anchor command did not return a transaction hash.");
            }
            return txHash.trim();
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalArgumentException("Hardhat anchoring failed.", ex);
        }
    }

    private java.io.File resolveHardhatProjectDirectory() {
        java.io.File current = new java.io.File(System.getProperty("user.dir"));
        for (int depth = 0; depth < 8 && current != null; depth++) {
            if (isHardhatDirectory(current)) {
                return current;
            }
            java.io.File nested = new java.io.File(current, "hardhat");
            if (isHardhatDirectory(nested)) {
                return nested;
            }
            current = current.getParentFile();
        }
        return new java.io.File(System.getProperty("user.dir"));
    }

    private boolean isHardhatDirectory(java.io.File dir) {
        return dir != null
                && dir.isDirectory()
                && new java.io.File(dir, "package.json").isFile()
                && new java.io.File(dir, "scripts/anchor.js").isFile();
    }

    private String defaultHardhatAnchorCommand() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return "set \"HARDHAT_DRY_RUN=true\" && npx.cmd hardhat run scripts/anchor.js --network localhost";
        }
        return "HARDHAT_DRY_RUN=true npx hardhat run scripts/anchor.js --network localhost";
    }

    private ProcessBuilder buildShellCommand(String command) {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("win")) {
            return new ProcessBuilder("cmd", "/c", command);
        }
        return new ProcessBuilder("sh", "-lc", command);
    }

    private String extractTxHash(String output) {
        if (isBlank(output)) {
            return null;
        }
        Matcher matcher = TX_HASH_PATTERN.matcher(output);
        if (matcher.find()) {
            return matcher.group();
        }

        try {
            Map<String, Object> parsed = objectMapper.readValue(output, new TypeReference<Map<String, Object>>() {
            });
            Object txHash = parsed.get("txHash");
            if (txHash == null) {
                txHash = parsed.get("transactionHash");
            }
            if (txHash != null && TX_HASH_PATTERN.matcher(String.valueOf(txHash)).matches()) {
                return String.valueOf(txHash);
            }
        } catch (IOException ignore) {
            // output may be plain text
        }
        return null;
    }

    private EncryptedPayload encryptSignedCredential(String signedVcJson) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            SecretKey key = keyGenerator.generateKey();

            byte[] iv = new byte[12];
            java.security.SecureRandom.getInstanceStrong().nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] cipherText = cipher.doFinal(signedVcJson.getBytes(StandardCharsets.UTF_8));

            byte[] packed = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, packed, 0, iv.length);
            System.arraycopy(cipherText, 0, packed, iv.length, cipherText.length);

            return new EncryptedPayload(packed, Base64.getEncoder().encodeToString(key.getEncoded()));
        } catch (Exception ex) {
            throw new IllegalArgumentException("Could not AES-encrypt signed VC.", ex);
        }
    }

    private String uploadEncryptedVcToPinata(byte[] encryptedPayload, String credentialId) {
        PinataAuth pinataAuth = resolvePinataAuth(true);

        String boundary = "----ssi-pinata-" + UUID.randomUUID();
        String fileName = credentialId.replaceAll("\\s+", "_") + ".vc.enc";

        try {
            byte[] body = buildPinataMultipartBody(boundary, fileName, encryptedPayload);

            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(new URI("https://api.pinata.cloud/pinning/pinFileToIPFS"))
                    .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));

            if (!isBlank(pinataAuth.jwt())) {
                builder.header("Authorization", "Bearer " + pinataAuth.jwt());
            } else {
                builder.header("pinata_api_key", pinataAuth.apiKey());
                builder.header("pinata_secret_api_key", pinataAuth.apiSecret());
            }

            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                String apiMessage = readApiMessage(response.body());
                throw new IllegalArgumentException(firstNonBlank(apiMessage, "Pinata upload failed."));
            }

            Map<String, Object> parsed = objectMapper.readValue(
                    response.body(),
                    new TypeReference<Map<String, Object>>() {
                    }
            );
            String ipfsHash = parsed.get("IpfsHash") == null ? null : String.valueOf(parsed.get("IpfsHash"));
            if (isBlank(ipfsHash)) {
                throw new IllegalArgumentException("Pinata response missing IpfsHash.");
            }
            return ipfsHash.trim();
        } catch (IOException | InterruptedException | URISyntaxException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalArgumentException("Pinata upload failed.", ex);
        }
    }

    private byte[] buildPinataMultipartBody(String boundary, String fileName, byte[] encryptedPayload) throws IOException {
        String metadataJson = objectMapper.writeValueAsString(Map.of("name", fileName));
        String separator = "--" + boundary + "\r\n";

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(separator.getBytes(StandardCharsets.UTF_8));
        stream.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"\r\n")
                .getBytes(StandardCharsets.UTF_8));
        stream.write("Content-Type: application/octet-stream\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        stream.write(encryptedPayload);
        stream.write("\r\n".getBytes(StandardCharsets.UTF_8));

        stream.write(separator.getBytes(StandardCharsets.UTF_8));
        stream.write("Content-Disposition: form-data; name=\"pinataMetadata\"\r\n\r\n".getBytes(StandardCharsets.UTF_8));
        stream.write(metadataJson.getBytes(StandardCharsets.UTF_8));
        stream.write("\r\n".getBytes(StandardCharsets.UTF_8));

        stream.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        return stream.toByteArray();
    }

    private String readApiMessage(String responseBody) {
        if (isBlank(responseBody)) {
            return null;
        }
        try {
            Map<String, Object> parsed = objectMapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {
            });
            Object message = parsed.get("message");
            return message == null ? null : String.valueOf(message);
        } catch (IOException ex) {
            return null;
        }
    }

    private record BbsSignResult(Map<String, Object> signedCredential, String signatureSuite) {
    }

    private record EncryptedPayload(byte[] blob, String keyBase64) {
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
        if (isBlank(request.vcSchema())) {
            throw new IllegalArgumentException("vcSchema is required.");
        }
        if (request.claims() == null) {
            throw new IllegalArgumentException("claims are required.");
        }
    }

    private void unpinCidIfConfigured(String cid) {
        if (isBlank(cid) || "REMOVED".equalsIgnoreCase(cid)) {
            return;
        }
        PinataAuth pinataAuth = resolvePinataAuth(false);
        if (!pinataAuth.isConfigured()) {
            return;
        }

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create("https://api.pinata.cloud/pinning/unpin/" + cid))
                .DELETE();

        if (!isBlank(pinataAuth.jwt())) {
            builder.header("Authorization", "Bearer " + pinataAuth.jwt());
        } else {
            builder.header("pinata_api_key", pinataAuth.apiKey());
            builder.header("pinata_secret_api_key", pinataAuth.apiSecret());
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

    private PinataAuth resolvePinataAuth(boolean required) {
        String jwt = firstNonBlank(
                pinataJwt,
                firstNonBlank(System.getenv("PINATA_JWT"), firstNonBlank(System.getProperty("PINATA_JWT"), null))
        );
        String apiKey = firstNonBlank(
                pinataApiKey,
                firstNonBlank(System.getenv("PINATA_API_KEY"), firstNonBlank(System.getProperty("PINATA_API_KEY"), null))
        );
        String apiSecret = firstNonBlank(
                pinataApiSecret,
                firstNonBlank(System.getenv("PINATA_API_SECRET"), firstNonBlank(System.getProperty("PINATA_API_SECRET"), null))
        );

        PinataAuth auth = new PinataAuth(trimOrNull(jwt), trimOrNull(apiKey), trimOrNull(apiSecret));
        if (required && !auth.isConfigured()) {
            throw new IllegalArgumentException(
                    "Pinata credentials are missing. Configure PINATA_JWT or PINATA_API_KEY + PINATA_API_SECRET."
            );
        }
        return auth;
    }

    private String trimOrNull(String value) {
        return isBlank(value) ? null : value.trim();
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

    private record PinataAuth(String jwt, String apiKey, String apiSecret) {
        private boolean isConfigured() {
            return hasText(jwt) || (hasText(apiKey) && hasText(apiSecret));
        }

        private static boolean hasText(String value) {
            return value != null && !value.isBlank();
        }
    }
}
