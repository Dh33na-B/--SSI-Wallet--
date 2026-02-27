package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.holder.ShareProofRequest;
import SSI.Wallet.Identity.dto.verifier.ProofRequestSummaryResponse;
import SSI.Wallet.Identity.dto.verifier.RequestProofRequest;
import SSI.Wallet.Identity.dto.verifier.VerificationDecisionRequest;
import SSI.Wallet.Identity.dto.verifier.VerifierCredentialOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerifierHolderOptionResponse;
import SSI.Wallet.Identity.dto.verifier.VerifyCredentialRequest;
import SSI.Wallet.Identity.model.entity.AuditLogEntity;
import SSI.Wallet.Identity.model.entity.CredentialEntity;
import SSI.Wallet.Identity.model.entity.ProofLogEntity;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.entity.VerificationRequestEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.model.enums.VerificationRequestStatus;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.ProofLogRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.repository.VerificationRequestRepository;
import SSI.Wallet.Identity.service.VerifierService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.web3j.crypto.Hash;

@Service
@RequiredArgsConstructor
@Transactional
public class VerifierServiceImpl implements VerifierService {

    private final UserRepository userRepository;
    private final CredentialRepository credentialRepository;
    private final VerificationRequestRepository verificationRequestRepository;
    private final ProofLogRepository proofLogRepository;
    private final AuditLogRepository auditLogRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newHttpClient();

    @Value("${bbs.signer.base-url:http://localhost:8085}")
    private String bbsSignerBaseUrl;

    @Value("${bbs.signer.auth-token:}")
    private String bbsSignerAuthToken;

    @Value("${hardhat.verify.command:}")
    private String hardhatVerifyCommand;

    @Override
    public ProofRequestSummaryResponse requestProof(RequestProofRequest request) {
        if (request == null || request.verifierId() == null || request.holderId() == null || isBlank(request.credentialId())) {
            throw new IllegalArgumentException("verifierId, holderId and credentialId are required.");
        }

        UserEntity verifier = getVerifier(request.verifierId());
        UserEntity holder = getHolder(request.holderId());
        CredentialEntity credential = getCredentialOrThrow(request.credentialId());
        ensureCredentialBelongsToHolder(credential, holder);

        List<String> requestedFields = normalizeFields(request.requestedFields(), true);
        VerificationRequestEntity created = verificationRequestRepository.save(
                VerificationRequestEntity.builder()
                        .credential(credential)
                        .holder(holder)
                        .verifier(verifier)
                        .requestedFields(writeJson(requestedFields))
                        .purpose(trimToNull(request.purpose()))
                        .expiresAt(request.expiresAt())
                        .status(VerificationRequestStatus.REQUESTED)
                        .build()
        );

        createAuditLog(verifier, "REQUEST_PROOF", "VERIFICATION_REQUEST", created.getId().toString());
        return toSummary(created);
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProofRequestSummaryResponse> getVerifierRequests(UUID verifierId) {
        getVerifier(verifierId);
        return verificationRequestRepository.findByVerifierIdOrderByCreatedAtDesc(verifierId).stream()
                .map(this::toSummary)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProofRequestSummaryResponse> getHolderRequests(UUID holderId) {
        getHolder(holderId);
        return verificationRequestRepository.findByHolderIdOrderByCreatedAtDesc(holderId).stream()
                .map(this::toSummary)
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<ProofLogEntity> getVerifierHistory(UUID verifierId) {
        getVerifier(verifierId);
        return proofLogRepository.findByVerifierIdOrderByVerifiedAtDesc(verifierId);
    }

    @Override
    @Transactional(readOnly = true)
    public List<VerifierHolderOptionResponse> getVerifierHolders(UUID verifierId) {
        getVerifier(verifierId);
        return userRepository.findByRoleOrderByCreatedAtAsc(UserRole.USER).stream()
                .map(holder -> new VerifierHolderOptionResponse(holder.getId(), holder.getWalletAddress()))
                .toList();
    }

    @Override
    @Transactional(readOnly = true)
    public List<VerifierCredentialOptionResponse> getVerifierCredentialOptions(UUID verifierId, UUID holderId) {
        getVerifier(verifierId);
        getHolder(holderId);

        Map<String, CredentialEntity> deduped = new LinkedHashMap<>();
        for (CredentialEntity credential : credentialRepository.findByHolderId(holderId)) {
            deduped.putIfAbsent(credential.getCredentialId(), credential);
        }
        for (CredentialEntity credential : credentialRepository.findByDocumentUserId(holderId)) {
            deduped.putIfAbsent(credential.getCredentialId(), credential);
        }

        return deduped.values().stream()
                .sorted(Comparator.comparing(CredentialEntity::getIssuedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .map(credential -> new VerifierCredentialOptionResponse(
                        credential.getCredentialId(),
                        deriveSchemaLabel(credential),
                        credential.getRevoked(),
                        credential.getIssuedAt(),
                        credential.getExpiresAt()
                ))
                .toList();
    }

    @Override
    public ProofRequestSummaryResponse processHolderProof(ShareProofRequest request) {
        if (request == null || request.holderId() == null || request.requestId() == null) {
            throw new IllegalArgumentException("holderId and requestId are required.");
        }

        UserEntity holder = getHolder(request.holderId());
        VerificationRequestEntity verificationRequest = verificationRequestRepository
                .findByIdAndHolderId(request.requestId(), holder.getId())
                .orElseThrow(() -> new IllegalArgumentException("Verification request not found: " + request.requestId()));

        if (!VerificationRequestStatus.REQUESTED.equals(verificationRequest.getStatus())) {
            throw new IllegalArgumentException("Verification request is already finalized: " + verificationRequest.getId());
        }
        if (verificationRequest.getExpiresAt() != null && verificationRequest.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException("Verification request expired at " + verificationRequest.getExpiresAt());
        }

        List<String> requestedFields = readStringList(verificationRequest.getRequestedFields());
        List<String> disclosedFields = normalizeFields(request.disclosedFields(), false);
        ensureSubset(disclosedFields, requestedFields);
        verificationRequest.setDisclosedFields(writeJson(disclosedFields));
        verificationRequest.setRespondedAt(LocalDateTime.now());

        if (disclosedFields.isEmpty()) {
            verificationRequest.setStatus(VerificationRequestStatus.HOLDER_DECLINED);
            verificationRequest.setVerificationStatus(Boolean.FALSE);
            verificationRequest.setVerificationMessage("Holder declined to disclose requested attributes.");
            verificationRequestRepository.save(verificationRequest);
            createAuditLog(holder, "HOLDER_DECLINED_PROOF", "VERIFICATION_REQUEST", verificationRequest.getId().toString());
            return toSummary(verificationRequest);
        }
        if (request.signedCredential() == null || request.signedCredential().isEmpty()) {
            throw new IllegalArgumentException("signedCredential is required.");
        }

        ProofPackage proofPackage = resolveProofPackage(request.signedCredential(), disclosedFields, request);
        verificationRequest.setProofValue(proofPackage.proofValue());
        verificationRequest.setProofNonce(proofPackage.proofNonce());
        verificationRequest.setRevealedMessages(writeJson(proofPackage.revealedMessages()));

        verifyAndPersist(verificationRequest, request.signedCredential(), disclosedFields, proofPackage);
        createAuditLog(holder, "SHARE_PROOF", "VERIFICATION_REQUEST", verificationRequest.getId().toString());
        return toSummary(verificationRequest);
    }

    @Override
    public ProofLogEntity verifyCredential(VerifyCredentialRequest request) {
        if (request == null || request.verifierId() == null || request.requestId() == null) {
            throw new IllegalArgumentException("verifierId and requestId are required.");
        }

        UserEntity verifier = getVerifier(request.verifierId());
        VerificationRequestEntity verificationRequest = verificationRequestRepository
                .findByIdAndVerifierId(request.requestId(), verifier.getId())
                .orElseThrow(() -> new IllegalArgumentException("Verification request not found: " + request.requestId()));

        if (isBlank(verificationRequest.getProofValue()) || isBlank(verificationRequest.getProofNonce())) {
            throw new IllegalArgumentException("Holder proof not submitted yet.");
        }

        proofLogRepository.findTopByVerificationRequestIdOrderByVerifiedAtDesc(verificationRequest.getId())
                .orElseThrow(() -> new IllegalArgumentException("No proof verification log found for request " + verificationRequest.getId()));

        List<String> disclosedFields = readStringList(verificationRequest.getDisclosedFields());
        ProofPackage proofPackage = new ProofPackage(
                verificationRequest.getProofValue(),
                verificationRequest.getProofNonce(),
                readStringList(verificationRequest.getRevealedMessages())
        );
        return verifyAndPersist(verificationRequest, null, disclosedFields, proofPackage);
    }

    @Override
    public ProofLogEntity submitDecision(VerificationDecisionRequest request) {
        if (request == null || request.verifierId() == null || isBlank(request.credentialId())) {
            throw new IllegalArgumentException("verifierId and credentialId are required.");
        }

        UserEntity verifier = getVerifier(request.verifierId());
        CredentialEntity credential = getCredentialOrThrow(request.credentialId());

        ProofLogEntity created = proofLogRepository.save(
                ProofLogEntity.builder()
                        .credential(credential)
                        .verifier(verifier)
                        .verificationStatus(request.accepted())
                        .notes(trimToNull(request.notes()))
                        .build()
        );
        createAuditLog(verifier, "DECISION_" + (request.accepted() ? "ACCEPT" : "REJECT"), "CREDENTIAL", credential.getCredentialId());
        return created;
    }

    private ProofLogEntity verifyAndPersist(
            VerificationRequestEntity verificationRequest,
            Map<String, Object> signedCredential,
            List<String> disclosedFields,
            ProofPackage proofPackage
    ) {
        boolean signatureValid = verifyProofWithSigner(signedCredential, disclosedFields, proofPackage);
        boolean vcHashMatches = signedCredential == null ? Boolean.TRUE.equals(verificationRequest.getVcHashMatches()) : verifyHashMatches(signedCredential, verificationRequest.getCredential().getVcHash());
        BlockchainStatus chain = checkBlockchainStatus(verificationRequest.getCredential().getCredentialId(), verificationRequest.getCredential().getVcHash());
        vcHashMatches = vcHashMatches && chain.vcHashMatches();

        boolean valid = signatureValid && chain.anchored() && !chain.revoked() && vcHashMatches;
        String statusMessage = buildStatusMessage(valid, signatureValid, vcHashMatches, chain);
        verificationRequest.setSignatureValid(signatureValid);
        verificationRequest.setBlockchainAnchored(chain.anchored());
        verificationRequest.setBlockchainRevoked(chain.revoked());
        verificationRequest.setVcHashMatches(vcHashMatches);
        verificationRequest.setVerificationStatus(valid);
        verificationRequest.setVerifiedAt(LocalDateTime.now());
        verificationRequest.setStatus(valid ? VerificationRequestStatus.VERIFIED_VALID : VerificationRequestStatus.VERIFIED_INVALID);
        verificationRequest.setVerificationMessage(statusMessage);
        verificationRequestRepository.save(verificationRequest);

        ProofLogEntity created = proofLogRepository.save(
                ProofLogEntity.builder()
                        .credential(verificationRequest.getCredential())
                        .verifier(verificationRequest.getVerifier())
                        .verificationRequest(verificationRequest)
                        .verificationStatus(valid)
                        .signatureValid(signatureValid)
                        .blockchainAnchored(chain.anchored())
                        .blockchainRevoked(chain.revoked())
                        .vcHashMatches(vcHashMatches)
                        .revealedFields(writeJson(disclosedFields))
                        .notes(statusMessage)
                        .build()
        );
        createAuditLog(verificationRequest.getVerifier(), "VERIFY_PROOF", "VERIFICATION_REQUEST", verificationRequest.getId().toString());
        return created;
    }

    private String buildStatusMessage(boolean valid, boolean signatureValid, boolean vcHashMatches, BlockchainStatus chain) {
        if (valid) {
            return "Proof signature valid, VC hash matched, and credential is active on chain.";
        }

        List<String> issues = new ArrayList<>();
        if (!signatureValid) {
            issues.add("BBS+ proof verification failed.");
        }
        if (!chain.anchored()) {
            issues.add("Credential hash not anchored on chain.");
        }
        if (chain.revoked()) {
            issues.add("Credential is revoked on chain.");
        }
        if (!vcHashMatches) {
            issues.add("Credential hash mismatch.");
        }
        if (!isBlank(chain.message())) {
            issues.add(chain.message());
        }
        if (issues.isEmpty()) {
            return "Verification failed.";
        }
        return String.join(" ", issues);
    }

    private ProofPackage resolveProofPackage(Map<String, Object> signedCredential, List<String> disclosedFields, ShareProofRequest request) {
        String proofValue = trimToNull(request.proofValue());
        String proofNonce = trimToNull(request.proofNonce());
        List<String> revealedMessages = normalizeFields(request.revealedMessages(), false);

        if (!isBlank(proofValue) && !isBlank(proofNonce) && !revealedMessages.isEmpty()) {
            return new ProofPackage(proofValue, proofNonce, revealedMessages);
        }

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("signedCredential", signedCredential);
        payload.put("revealFields", disclosedFields);
        Map<String, Object> response = postJson("/v1/credentials/proof", payload, "BBS proof derivation failed.");
        return new ProofPackage(
                requireText(response, "proofValue", "Signer response missing proofValue."),
                requireText(response, "nonce", "Signer response missing nonce."),
                normalizeFields(asList(response.get("revealedMessages")), false)
        );
    }

    private boolean verifyProofWithSigner(Map<String, Object> signedCredential, List<String> disclosedFields, ProofPackage proofPackage) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("proofValue", proofPackage.proofValue());
        payload.put("nonce", proofPackage.proofNonce());

        if (signedCredential != null && !signedCredential.isEmpty()) {
            payload.put("signedCredential", signedCredential);
            payload.put("revealFields", disclosedFields);
        } else {
            payload.put("revealedMessages", proofPackage.revealedMessages());
        }

        Map<String, Object> response = postJson("/v1/credentials/proof/verify", payload, "BBS proof verification failed.");
        return Boolean.TRUE.equals(response.get("valid"));
    }

    private boolean verifyHashMatches(Map<String, Object> signedCredential, String expectedHash) {
        try {
            String hash = Hash.sha3String(objectMapper.writeValueAsString(signedCredential));
            return normalizeHex(hash).equalsIgnoreCase(normalizeHex(expectedHash));
        } catch (IOException ex) {
            return false;
        }
    }

    private BlockchainStatus checkBlockchainStatus(String credentialId, String vcHash) {
        try {
            String command = isBlank(hardhatVerifyCommand)
                    ? (isWindows() ? "set \"HARDHAT_DRY_RUN=true\" && npx.cmd hardhat run scripts/check.js --network localhost" : "HARDHAT_DRY_RUN=true npx hardhat run scripts/check.js --network localhost")
                    : hardhatVerifyCommand.trim();

            ProcessBuilder builder = new ProcessBuilder(isWindows() ? new String[]{"cmd", "/c", command} : new String[]{"sh", "-lc", command});
            builder.directory(resolveHardhatDirectory());
            builder.environment().put("CREDENTIAL_ID", credentialId);
            builder.environment().put("VC_HASH", vcHash);

            Process process = builder.start();
            if (!process.waitFor(90, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new BlockchainStatus(false, false, false, "Hardhat verification command timed out.");
            }

            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                    + "\n"
                    + new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
            if (process.exitValue() != 0) {
                return new BlockchainStatus(false, false, false, trimToNull(output));
            }

            Map<String, Object> parsed = parseJson(output);
            boolean anchored = parsed != null && Boolean.TRUE.equals(parsed.get("anchored"));
            boolean revoked = parsed != null && Boolean.TRUE.equals(parsed.get("revoked"));
            boolean vcHashMatches = parsed != null && Boolean.TRUE.equals(parsed.get("vcHashMatches"));
            String message = parsed == null ? "Could not parse blockchain check output." : trimToNull((String) parsed.get("message"));
            return new BlockchainStatus(anchored, revoked, vcHashMatches, message);
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return new BlockchainStatus(false, false, false, "Blockchain check failed.");
        }
    }

    private java.io.File resolveHardhatDirectory() {
        java.io.File current = new java.io.File(System.getProperty("user.dir"));
        for (int i = 0; i < 8 && current != null; i++) {
            if (new java.io.File(current, "scripts/check.js").isFile()) {
                return current;
            }
            java.io.File nested = new java.io.File(current, "hardhat");
            if (new java.io.File(nested, "scripts/check.js").isFile()) {
                return nested;
            }
            current = current.getParentFile();
        }
        return new java.io.File(System.getProperty("user.dir"));
    }

    private Map<String, Object> postJson(String path, Map<String, Object> payload, String fallbackMessage) {
        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create((isBlank(bbsSignerBaseUrl) ? "http://localhost:8085" : bbsSignerBaseUrl.trim()) + path))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payload), StandardCharsets.UTF_8));
            if (!isBlank(bbsSignerAuthToken)) {
                builder.header("Authorization", "Bearer " + bbsSignerAuthToken.trim());
            }
            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() >= 300) {
                String apiMessage = readApiMessage(response.body());
                if (response.statusCode() == 401) {
                    throw new IllegalArgumentException(
                            "BBS signer unauthorized. Ensure BBS_SIGNER_AUTH_TOKEN matches signer service."
                    );
                }
                throw new IllegalArgumentException(isBlank(apiMessage) ? fallbackMessage : apiMessage);
            }
            return objectMapper.readValue(response.body(), new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException | InterruptedException ex) {
            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalArgumentException(fallbackMessage);
        }
    }

    private Map<String, Object> parseJson(String mixedOutput) {
        if (isBlank(mixedOutput)) {
            return null;
        }
        try {
            return objectMapper.readValue(mixedOutput.trim(), new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException ignore) {
            int close = mixedOutput.lastIndexOf('}');
            int open = mixedOutput.lastIndexOf('{', close);
            if (open < 0 || close < 0) {
                return null;
            }
            try {
                return objectMapper.readValue(mixedOutput.substring(open, close + 1), new TypeReference<Map<String, Object>>() {
                });
            } catch (IOException ex) {
                return null;
            }
        }
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

    private void ensureCredentialBelongsToHolder(CredentialEntity credential, UserEntity holder) {
        UserEntity credentialHolder = credential.getHolder() != null ? credential.getHolder() : credential.getDocument() == null ? null : credential.getDocument().getUser();
        if (credentialHolder == null || !credentialHolder.getId().equals(holder.getId())) {
            throw new IllegalArgumentException("Credential does not belong to selected holder.");
        }
    }

    private UserEntity getVerifier(UUID verifierId) {
        return userRepository.findByIdAndRole(verifierId, UserRole.VERIFIER)
                .orElseThrow(() -> new IllegalArgumentException("Verifier not found: " + verifierId));
    }

    private UserEntity getHolder(UUID holderId) {
        return userRepository.findByIdAndRole(holderId, UserRole.USER)
                .orElseThrow(() -> new IllegalArgumentException("Holder not found: " + holderId));
    }

    private CredentialEntity getCredentialOrThrow(String credentialId) {
        return credentialRepository.findByCredentialId(credentialId.trim())
                .orElseThrow(() -> new IllegalArgumentException("Credential not found: " + credentialId));
    }

    private ProofRequestSummaryResponse toSummary(VerificationRequestEntity request) {
        return new ProofRequestSummaryResponse(
                request.getId(),
                request.getCredential() == null ? null : request.getCredential().getCredentialId(),
                request.getHolder() == null ? null : request.getHolder().getId(),
                request.getHolder() == null ? null : request.getHolder().getWalletAddress(),
                request.getVerifier() == null ? null : request.getVerifier().getId(),
                request.getVerifier() == null ? null : request.getVerifier().getWalletAddress(),
                readStringList(request.getRequestedFields()),
                readStringList(request.getDisclosedFields()),
                request.getPurpose(),
                request.getStatus() == null ? null : request.getStatus().name(),
                request.getVerificationStatus(),
                request.getSignatureValid(),
                request.getBlockchainAnchored(),
                request.getBlockchainRevoked(),
                request.getVcHashMatches(),
                request.getVerificationMessage(),
                request.getCreatedAt(),
                request.getRespondedAt(),
                request.getVerifiedAt(),
                request.getExpiresAt()
        );
    }

    private List<String> readStringList(String json) {
        if (isBlank(json)) {
            return List.of();
        }
        try {
            return normalizeFields(objectMapper.readValue(json, new TypeReference<List<String>>() {
            }), false);
        } catch (IOException ex) {
            return List.of();
        }
    }

    private List<String> normalizeFields(List<String> raw, boolean requireAtLeastOne) {
        if (raw == null) {
            if (requireAtLeastOne) {
                throw new IllegalArgumentException("At least one attribute path is required.");
            }
            return List.of();
        }
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String item : raw) {
            String value = trimToNull(item);
            if (value != null) {
                out.add(value);
            }
        }
        if (requireAtLeastOne && out.isEmpty()) {
            throw new IllegalArgumentException("At least one attribute path is required.");
        }
        return List.copyOf(out);
    }

    private void ensureSubset(List<String> disclosed, List<String> requested) {
        for (String field : disclosed) {
            if (!requested.contains(field)) {
                throw new IllegalArgumentException("Disclosed field `" + field + "` was not requested.");
            }
        }
    }

    private List<String> asList(Object value) {
        if (!(value instanceof List<?> list)) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Object item : list) {
            if (item != null) {
                out.add(String.valueOf(item));
            }
        }
        return out;
    }

    private String deriveSchemaLabel(CredentialEntity credential) {
        if (credential.getDocument() != null && credential.getDocument().getDocumentType() != null) {
            return credential.getDocument().getDocumentType().getName();
        }
        return isBlank(credential.getSignatureSuite()) ? "VerifiableCredential" : credential.getSignatureSuite();
    }

    private String requireText(Map<String, Object> payload, String key, String error) {
        String value = payload.get(key) == null ? null : String.valueOf(payload.get(key));
        if (isBlank(value)) {
            throw new IllegalArgumentException(error);
        }
        return value.trim();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (IOException ex) {
            throw new IllegalArgumentException("Could not serialize payload.");
        }
    }

    private String normalizeHex(String value) {
        if (isBlank(value)) {
            return "";
        }
        String trimmed = value.trim();
        return (trimmed.startsWith("0x") || trimmed.startsWith("0X")) ? trimmed : "0x" + trimmed;
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
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

    private record ProofPackage(String proofValue, String proofNonce, List<String> revealedMessages) {
    }

    private record BlockchainStatus(boolean anchored, boolean revoked, boolean vcHashMatches, String message) {
    }
}
