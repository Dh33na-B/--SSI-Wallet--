package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record AccessControlRequest(
        UUID holderId,
        UUID documentId,
        UUID recipientUserId,
        String encryptedKey
) {
}
