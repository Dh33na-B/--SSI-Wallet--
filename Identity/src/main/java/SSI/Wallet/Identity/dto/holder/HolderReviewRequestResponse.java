package SSI.Wallet.Identity.dto.holder;

import java.time.LocalDateTime;
import java.util.UUID;

public record HolderReviewRequestResponse(
        UUID requestId,
        UUID documentId,
        String fileName,
        String documentType,
        UUID issuerId,
        String issuerWallet,
        String issuerEncryptionPublicKey,
        String status,
        String issuerNote,
        String holderNote,
        String holderEncryptedKey,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
