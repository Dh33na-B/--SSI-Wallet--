package SSI.Wallet.Identity.dto.holder;

public record HolderCredentialAccessResponse(
        String credentialId,
        String vcIpfsCid,
        String encryptedKey,
        String vcHash,
        String signatureSuite,
        Boolean revoked,
        String issuerWallet
) {
}

