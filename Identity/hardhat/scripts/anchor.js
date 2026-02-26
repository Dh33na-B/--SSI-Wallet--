import { Contract, JsonRpcProvider, Wallet, keccak256, toUtf8Bytes } from "ethers";

async function main() {
  const vcHash = process.env.VC_HASH;
  const credentialId = process.env.CREDENTIAL_ID;

  if (!vcHash || !vcHash.startsWith("0x") || vcHash.length !== 66) {
    throw new Error("VC_HASH must be a 0x-prefixed 32-byte hash.");
  }
  if (!credentialId) {
    throw new Error("CREDENTIAL_ID is required.");
  }

  // Optional dry-run mode for local testing without chain tx.
  if (String(process.env.HARDHAT_DRY_RUN || "").toLowerCase() === "true") {
    const simulated = keccak256(toUtf8Bytes(`${credentialId}|${vcHash}|dry-run`));
    console.log(JSON.stringify({ txHash: simulated, dryRun: true }));
    return;
  }

  const contractAddress = process.env.CREDENTIAL_REGISTRY_ADDRESS;
  if (!contractAddress) {
    throw new Error("CREDENTIAL_REGISTRY_ADDRESS is required.");
  }

  const rpcUrl = process.env.HARDHAT_RPC_URL || "http://127.0.0.1:8545";
  const privateKey = process.env.HARDHAT_PRIVATE_KEY;
  if (!privateKey) {
    throw new Error("HARDHAT_PRIVATE_KEY is required.");
  }
  const provider = new JsonRpcProvider(rpcUrl);
  const signer = new Wallet(privateKey, provider);

  const abi = [
    "function anchorCredential(string credentialId, bytes32 vcHash) external returns (bool)"
  ];

  const contract = new Contract(contractAddress, abi, signer);
  const tx = await contract.anchorCredential(credentialId, vcHash);
  const receipt = await tx.wait();

  console.log(
    JSON.stringify({
      txHash: tx.hash,
      blockNumber: receipt?.blockNumber ?? null
    })
  );
}

main().catch((error) => {
  console.error(error?.message || String(error));
  process.exit(1);
});
