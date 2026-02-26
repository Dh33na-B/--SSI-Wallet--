package SSI.Wallet.Identity.dto.issuer;

import java.time.LocalDateTime;
import java.util.UUID;

public record IssuerDocumentQueueItemResponse(
        UUID id,
        UUID holderId,
        String holderWallet,
        String fileName,
        String documentType,
        String status,
        LocalDateTime uploadedAt,
        UUID reviewRequestId,
        String reviewStatus
) {
}
