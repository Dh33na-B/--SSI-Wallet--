package SSI.Wallet.Identity.dto.verifier;

import java.util.UUID;

public record VerificationDecisionRequest(
        UUID verifierId,
        String credentialId,
        boolean accepted,
        String notes
) {
}
