package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record IssuerDocumentDecisionRequest(
        UUID issuerId,
        UUID documentId,
        boolean approved,
        String reason,
        boolean removePreviousCid
) {
}
