package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record RespondReviewRequest(
        UUID holderId,
        UUID requestId,
        boolean approved,
        String encryptedKeyForIssuer,
        String note
) {
}
