package SSI.Wallet.Identity.dto.verifier;

import java.time.LocalDateTime;

public record VerifierCredentialOptionResponse(
        String credentialId,
        String schema,
        Boolean revoked,
        LocalDateTime issuedAt,
        LocalDateTime expiresAt
) {
}

