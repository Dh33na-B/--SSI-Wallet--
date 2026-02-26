import { network } from "hardhat";

async function main() {
  const connection = await network.connect();
  const { ethers } = connection;

  const registry = await ethers.deployContract("CredentialRegistry");
  await registry.waitForDeployment();

  const address = await registry.getAddress();
  const deployedOn = await ethers.provider.getNetwork();

  console.log(
    JSON.stringify(
      {
        contract: "CredentialRegistry",
        address,
        chainId: Number(deployedOn.chainId),
        network: network.name
      },
      null,
      2
    )
  );

  console.log(`setx CREDENTIAL_REGISTRY_ADDRESS "${address}"`);
}

main().catch((error) => {
  console.error(error?.message || String(error));
  process.exit(1);
});
