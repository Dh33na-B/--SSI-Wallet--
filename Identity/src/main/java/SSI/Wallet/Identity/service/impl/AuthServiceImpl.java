package SSI.Wallet.Identity.service.impl;

import SSI.Wallet.Identity.dto.auth.MetaMaskLoginRequest;
import SSI.Wallet.Identity.dto.auth.MetaMaskLoginResponse;
import SSI.Wallet.Identity.dto.auth.MetaMaskRemoveAccountRequest;
import SSI.Wallet.Identity.model.entity.UserEntity;
import SSI.Wallet.Identity.model.enums.UserRole;
import SSI.Wallet.Identity.repository.AuditLogRepository;
import SSI.Wallet.Identity.repository.CredentialRepository;
import SSI.Wallet.Identity.repository.DocumentKeyRepository;
import SSI.Wallet.Identity.repository.DocumentRepository;
import SSI.Wallet.Identity.repository.DocumentTypeRepository;
import SSI.Wallet.Identity.repository.ProofLogRepository;
import SSI.Wallet.Identity.repository.RevocationHistoryRepository;
import SSI.Wallet.Identity.repository.UserRepository;
import SSI.Wallet.Identity.service.AuthService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final DocumentRepository documentRepository;
    private final DocumentKeyRepository documentKeyRepository;
    private final DocumentTypeRepository documentTypeRepository;
    private final CredentialRepository credentialRepository;
    private final RevocationHistoryRepository revocationHistoryRepository;
    private final ProofLogRepository proofLogRepository;
    private final AuditLogRepository auditLogRepository;

    @Override
    public MetaMaskLoginResponse loginWithMetaMask(MetaMaskLoginRequest request) {
        validateRequest(request);

        String normalizedWallet = request.walletAddress().trim().toLowerCase();
        UserRole role = normalizeRole(request.role());

        UserEntity existing = userRepository.findByWalletAddressIgnoreCase(normalizedWallet).orElse(null);
        boolean isNewUser = existing == null;

        UserEntity persisted;
        if (isNewUser) {
            persisted = userRepository.save(
                    UserEntity.builder()
                            .walletAddress(normalizedWallet)
                            .role(role)
                            .build()
            );
        } else {
            if (!existing.getRole().equals(role)) {
                throw new IllegalArgumentException(
                        "Role mismatch for this wallet. This wallet is already bound to role: "
                                + existing.getRole().name()
                );
            }
            existing.setWalletAddress(normalizedWallet);
            persisted = userRepository.save(existing);
        }

        return new MetaMaskLoginResponse(
                persisted.getId(),
                persisted.getWalletAddress(),
                persisted.getRole().name(),
                isNewUser
        );
    }

    @Override
    public void removeMetaMaskAccount(MetaMaskRemoveAccountRequest request) {
        validateRemoveRequest(request);
        String normalizedWallet = request.walletAddress().trim().toLowerCase();

        UserEntity existing = userRepository.findByWalletAddressIgnoreCase(normalizedWallet)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Account not found for wallet: " + normalizedWallet
                ));

        cleanupUserReferences(existing.getId());

        try {
            userRepository.delete(existing);
            userRepository.flush();
        } catch (DataIntegrityViolationException ex) {
            throw new IllegalArgumentException(
                    "Unable to remove account because related records still reference this user."
            );
        }
    }

    private void validateRequest(MetaMaskLoginRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Login request is required.");
        }
        if (isBlank(request.walletAddress())) {
            throw new IllegalArgumentException("walletAddress is required.");
        }
        if (!request.walletAddress().startsWith("0x")) {
            throw new IllegalArgumentException("walletAddress must start with 0x.");
        }
        if (request.walletAddress().length() < 10 || request.walletAddress().length() > 100) {
            throw new IllegalArgumentException("walletAddress length is invalid.");
        }
        if (isBlank(request.role())) {
            throw new IllegalArgumentException("role is required.");
        }
        if (isBlank(request.signature())) {
            throw new IllegalArgumentException("signature is required.");
        }
        if (isBlank(request.message())) {
            throw new IllegalArgumentException("message is required.");
        }
        if (isBlank(request.nonce())) {
            throw new IllegalArgumentException("nonce is required.");
        }
    }

    private UserRole normalizeRole(String rawRole) {
        String normalized = rawRole == null ? "" : rawRole.trim().toUpperCase();
        if ("HOLDER".equals(normalized)) {
            return UserRole.USER;
        }
        try {
            return UserRole.valueOf(normalized);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Unsupported role: " + rawRole);
        }
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private void validateRemoveRequest(MetaMaskRemoveAccountRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Remove account request is required.");
        }
        if (isBlank(request.walletAddress())) {
            throw new IllegalArgumentException("walletAddress is required.");
        }
        if (!request.walletAddress().startsWith("0x")) {
            throw new IllegalArgumentException("walletAddress must start with 0x.");
        }
        if (request.walletAddress().length() < 10 || request.walletAddress().length() > 100) {
            throw new IllegalArgumentException("walletAddress length is invalid.");
        }
    }

    private void cleanupUserReferences(UUID userId) {
        documentKeyRepository.deleteByDocumentUserId(userId);
        credentialRepository.clearDocumentByDocumentOwnerId(userId);
        documentRepository.deleteByUserId(userId);

        documentKeyRepository.clearRecipientUserByUserId(userId);
        credentialRepository.clearIssuerByUserId(userId);
        revocationHistoryRepository.clearRevokedByUserId(userId);
        proofLogRepository.clearVerifierByUserId(userId);
        auditLogRepository.clearUserByUserId(userId);
        documentTypeRepository.clearCreatedByUserId(userId);
    }
}
