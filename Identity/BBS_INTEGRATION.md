# BBS+ Signing Integration (Spring Boot + Go)

## 1. Run the Go signer service

From `c:\SSI\bbs-signer-service`:

```bash
go run .
```

Optional env:

- `BBS_SIGNER_AUTH_TOKEN` to protect signing endpoints.
- `BBS_SIGNER_KEY_FILE` to change keystore path.

## 2. Configure Spring Boot

Set environment variables before starting `Identity`:

- `BBS_SIGNER_BASE_URL` (default `http://localhost:8085`)
- `BBS_SIGNER_AUTH_TOKEN` (must match signer if enabled)
- `PINATA_JWT` or `PINATA_API_KEY` + `PINATA_API_SECRET`
- `HARDHAT_ANCHOR_COMMAND` (optional)

Example hardhat command:

```bash
cd hardhat && npx hardhat run scripts/anchor.js --network localhost
```

The backend injects `VC_HASH` and `CREDENTIAL_ID` env vars into the command.

## 3. Issuer flow now

When issuer clicks **Sign + Encrypt + Anchor + Store VC**:

1. Spring builds unsigned VC payload from issuer input.
2. Spring calls Go service `/v1/credentials/sign` (BBS+ signature).
3. Spring computes `keccak256(signedVcJson)`.
4. Spring anchors hash using configured hardhat command.
5. Spring encrypts signed VC with AES-256-GCM (`K_vc`).
6. Spring calls Go `/v1/keys/wrap` to wrap `K_vc` for holder key.
7. Spring uploads encrypted VC blob to Pinata IPFS.
8. Spring stores CID + hash + tx hash + metadata in `credentials`.
9. Spring stores wrapped `K_vc` in `credential_keys`.

No issuer private signing key is exposed to frontend.
