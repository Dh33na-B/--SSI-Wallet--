package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record IssuerDocumentAccessResponse(
        UUID documentId,
        UUID holderId,
        String holderWallet,
        String holderEncryptionPublicKey,
        String fileName,
        String documentType,
        String ipfsCid,
        String encryptionIv,
        String encryptedKey,
        UUID reviewRequestId,
        String reviewStatus
) {
}
