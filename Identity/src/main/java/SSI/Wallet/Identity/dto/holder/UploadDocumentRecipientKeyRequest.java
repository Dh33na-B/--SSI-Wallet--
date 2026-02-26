package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record UploadDocumentRecipientKeyRequest(
        UUID recipientUserId,
        String encryptedKey
) {
}
