import { Contract, JsonRpcProvider } from "ethers";

function isHex32(value) {
  return typeof value === "string" && /^0x[a-fA-F0-9]{64}$/.test(value);
}

async function main() {
  const credentialId = process.env.CREDENTIAL_ID;
  const expectedVcHash = process.env.VC_HASH;

  if (!credentialId) {
    throw new Error("CREDENTIAL_ID is required.");
  }
  if (!isHex32(expectedVcHash)) {
    throw new Error("VC_HASH must be a 0x-prefixed 32-byte hash.");
  }

  if (String(process.env.HARDHAT_DRY_RUN || "").toLowerCase() === "true") {
    console.log(
      JSON.stringify({
        anchored: true,
        revoked: false,
        vcHashMatches: true,
        onChainVcHash: expectedVcHash,
        message: "Dry-run blockchain check."
      })
    );
    return;
  }

  const contractAddress = process.env.CREDENTIAL_REGISTRY_ADDRESS;
  if (!contractAddress) {
    throw new Error("CREDENTIAL_REGISTRY_ADDRESS is required.");
  }

  const rpcUrl = process.env.HARDHAT_RPC_URL || "http://127.0.0.1:8545";
  const provider = new JsonRpcProvider(rpcUrl);

  const abi = [
    "function getCredential(string credentialId) external view returns (bytes32 vcHash, bool anchored, bool revoked, uint256 anchoredAt, uint256 revokedAt)"
  ];

  const contract = new Contract(contractAddress, abi, provider);
  const record = await contract.getCredential(credentialId);

  const onChainVcHash = String(record.vcHash || "");
  const anchored = Boolean(record.anchored);
  const revoked = Boolean(record.revoked);
  const vcHashMatches = anchored && onChainVcHash.toLowerCase() === expectedVcHash.toLowerCase();

  console.log(
    JSON.stringify({
      anchored,
      revoked,
      vcHashMatches,
      onChainVcHash,
      message: anchored ? (revoked ? "Credential is revoked on chain." : "Credential is active on chain.") : "Credential hash not anchored on chain."
    })
  );
}

main().catch((error) => {
  console.error(error?.message || String(error));
  process.exit(1);
});
