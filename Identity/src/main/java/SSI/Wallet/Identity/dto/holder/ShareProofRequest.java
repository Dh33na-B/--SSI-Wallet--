package SSI.Wallet.Identity.dto.holder;

import java.util.List;
import java.util.Map;
import java.util.UUID;

public record ShareProofRequest(
        UUID holderId,
        UUID requestId,
        List<String> disclosedFields,
        Map<String, Object> signedCredential,
        String proofValue,
        String proofNonce,
        Map<String, Object> revealedClaims,
        List<String> revealedMessages
) {
}
