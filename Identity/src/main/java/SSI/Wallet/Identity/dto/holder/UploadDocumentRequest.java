package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record UploadDocumentRequest(
        UUID holderId,
        UUID documentTypeId,
        String newDocumentTypeName,
        String fileName,
        String ipfsCid,
        String encryptionIv,
        String encryptedKey
) {
}
