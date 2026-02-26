# BBS+ Signer Service (Go)

This microservice signs VC payloads using a server-side BBS+ private key (BLS12-381), and exposes REST APIs for:

- VC signing
- selective disclosure proof derivation
- selective disclosure proof verification
- wrapping symmetric keys for MetaMask-compatible `eth_decrypt`

## Run

```bash
go run .
```

Default bind address: `:8085`

## Environment

- `BBS_SIGNER_BIND_ADDRESS` (default `:8085`)
- `BBS_SIGNER_KEY_FILE` (default `./data/issuer-bbs-key.json`)
- `BBS_SIGNER_AUTH_TOKEN` (optional bearer token for protected endpoints)
- `BBS_SIGNER_DEFAULT_ISSUER` (optional fallback DID/wallet used in proof metadata)
- `BBS_SIGNER_DEFAULT_VERIFICATION_METHOD` (optional fallback, e.g. `did:ethr:0x...#bbs-key-1`)

## Endpoints

- `GET /healthz`
- `GET /v1/keys/public`
- `POST /v1/credentials/sign`
- `POST /v1/credentials/proof`
- `POST /v1/credentials/proof/verify`
- `POST /v1/keys/wrap`

When `BBS_SIGNER_AUTH_TOKEN` is set, all `POST /v1/*` endpoints require:

```http
Authorization: Bearer <token>
```

### Sign VC

`POST /v1/credentials/sign`

```json
{
  "credential": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "id": "VC-2026-001",
    "type": ["VerifiableCredential", "DegreeCredential-v1"],
    "issuer": "did:ethr:0xIssuer",
    "issuanceDate": "2026-02-26T18:20:00Z",
    "credentialSubject": {
      "id": "did:ethr:0xHolder",
      "name": "Alice"
    }
  },
  "verificationMethod": "did:ethr:0xIssuer#bbs-key-1",
  "proofPurpose": "assertionMethod"
}
```

Response includes `signedCredential` with `proof.type = BbsBlsSignature2020` and base64 `proofValue`.

### Derive selective disclosure proof (optional)

`POST /v1/credentials/proof`

```json
{
  "signedCredential": { "...": "..." },
  "revealFields": ["credentialSubject.name", "issuer"]
}
```

### Wrap symmetric key for holder

`POST /v1/keys/wrap`

```json
{
  "recipientPublicKeyBase64": "<metamask holder encryption public key>",
  "payloadBase64": "<base64 raw AES key bytes>"
}
```

Returns both JSON and hex envelopes in MetaMask-compatible `x25519-xsalsa20-poly1305` format.

### Verify selective disclosure proof

`POST /v1/credentials/proof/verify`

```json
{
  "signedCredential": { "...": "..." },
  "revealFields": ["credentialSubject.name", "issuer"],
  "proofValue": "<base64 proof>",
  "nonce": "<base64 nonce>"
}
```

Or when backend already persisted ordered canonical messages:

```json
{
  "revealedMessages": ["issuer=\"did:ethr:0x...\""],
  "proofValue": "<base64 proof>",
  "nonce": "<base64 nonce>"
}
```
