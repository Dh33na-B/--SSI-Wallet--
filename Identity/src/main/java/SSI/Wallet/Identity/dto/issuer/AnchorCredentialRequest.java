package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record AnchorCredentialRequest(
        UUID issuerId,
        String credentialId,
        String blockchainTxHash
) {
}
