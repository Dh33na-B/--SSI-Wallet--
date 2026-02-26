package SSI.Wallet.Identity.dto.auth;

import java.util.UUID;

public record MetaMaskLoginResponse(
        UUID userId,
        String walletAddress,
        String role,
        boolean isNewUser
) {
}
