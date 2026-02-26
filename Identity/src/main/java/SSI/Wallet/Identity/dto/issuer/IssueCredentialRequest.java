package SSI.Wallet.Identity.dto.issuer;

import java.time.LocalDateTime;
import java.util.UUID;

public record IssueCredentialRequest(
        UUID issuerId,
        UUID documentId,
        String credentialId,
        String vcIpfsCid,
        String vcHash,
        String signatureSuite,
        String blockchainTxHash,
        String holderEncryptedKey,
        LocalDateTime expiresAt
) {
}
