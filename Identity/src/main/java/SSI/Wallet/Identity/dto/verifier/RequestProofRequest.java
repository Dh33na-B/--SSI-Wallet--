package SSI.Wallet.Identity.dto.verifier;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

public record RequestProofRequest(
        UUID verifierId,
        UUID holderId,
        String credentialId,
        List<String> requestedFields,
        String purpose,
        LocalDateTime expiresAt
) {
}
