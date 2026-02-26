package SSI.Wallet.Identity.dto.auth;

public record MetaMaskLoginRequest(
        String walletAddress,
        String role,
        String signature,
        String message,
        String chainId,
        String nonce,
        String loginAt,
        String encryptionPublicKey
) {
}
