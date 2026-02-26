package SSI.Wallet.Identity.dto.issuer;

import java.util.UUID;

public record RevokeCredentialRequest(
        UUID issuerId,
        String credentialId,
        String reason
) {
}
