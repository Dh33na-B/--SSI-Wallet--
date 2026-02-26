package SSI.Wallet.Identity.dto.holder;

import java.util.UUID;

public record IssuerEncryptionKeyResponse(
        UUID issuerId,
        String walletAddress,
        String encryptionPublicKey
) {
}
