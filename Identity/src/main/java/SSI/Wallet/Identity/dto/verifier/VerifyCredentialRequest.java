package SSI.Wallet.Identity.dto.verifier;

import java.util.UUID;

public record VerifyCredentialRequest(
        UUID verifierId,
        String credentialId
) {
}
