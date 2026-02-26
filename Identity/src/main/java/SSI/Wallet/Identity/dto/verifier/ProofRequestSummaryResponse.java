package SSI.Wallet.Identity.dto.verifier;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public record ProofRequestSummaryResponse(
        UUID requestId,
        String credentialId,
        UUID holderId,
        String holderWallet,
        UUID verifierId,
        String verifierWallet,
        List<String> requestedFields,
        List<String> disclosedFields,
        String purpose,
        String status,
        Boolean verificationStatus,
        Boolean signatureValid,
        Boolean blockchainAnchored,
        Boolean blockchainRevoked,
        Boolean vcHashMatches,
        String verificationMessage,
        LocalDateTime createdAt,
        LocalDateTime respondedAt,
        LocalDateTime verifiedAt,
        LocalDateTime expiresAt
) {
}

