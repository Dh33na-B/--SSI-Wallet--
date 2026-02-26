package SSI.Wallet.Identity.dto.issuer;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

public record IssueCredentialRequest(
        UUID issuerId,
        UUID documentId,
        String credentialId,
        String vcSchema,
        Map<String, Object> claims,
        LocalDateTime expiresAt
) {
}
