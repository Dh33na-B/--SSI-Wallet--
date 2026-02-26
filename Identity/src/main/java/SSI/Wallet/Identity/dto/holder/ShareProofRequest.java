package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record ShareProofRequest(
        UUID holderId,
        String credentialId,
        UUID verifierId,
        String requestedFields
) {
}
