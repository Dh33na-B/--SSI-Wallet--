package SSI.Wallet.Identity.dto.verifier;

import java.util.UUID;

public record VerifierHolderOptionResponse(
        UUID holderId,
        String holderWallet
) {
}

