package SSI.Wallet.Identity.dto.verifier;

import java.util.UUID;

public record RequestProofRequest(
        UUID verifierId,
        UUID holderId,
        String credentialId,
        String requestedFields
) {
}
