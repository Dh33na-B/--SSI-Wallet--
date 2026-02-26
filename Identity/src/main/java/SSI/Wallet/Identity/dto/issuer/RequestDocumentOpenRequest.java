package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record RequestDocumentOpenRequest(
        UUID issuerId,
        UUID documentId,
        String issuerEncryptionPublicKey
) {
}
