package SSI.Wallet.Identity.dto.issuer;

import java.time.LocalDateTime;
import java.util.UUID;

public record IssuerReviewRequestResponse(
        UUID requestId,
        UUID documentId,
        String status,
        String issuerNote,
        String holderNote,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
}
