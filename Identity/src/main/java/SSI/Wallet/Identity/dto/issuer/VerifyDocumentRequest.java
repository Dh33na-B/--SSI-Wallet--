package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record VerifyDocumentRequest(
        UUID issuerId,
        UUID documentId,
        boolean approved
) {
}
