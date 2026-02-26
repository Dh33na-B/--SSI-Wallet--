import { defineConfig } from "hardhat/config";
import hardhatEthers from "@nomicfoundation/hardhat-ethers";
import hardhatVerify from "@nomicfoundation/hardhat-verify";

const localRpcUrl = process.env.HARDHAT_RPC_URL || "http://127.0.0.1:8545";
const localAccounts = process.env.HARDHAT_PRIVATE_KEY ? [process.env.HARDHAT_PRIVATE_KEY] : [];
const sepoliaRpcUrl = process.env.SEPOLIA_RPC_URL || "";
const sepoliaAccounts = process.env.SEPOLIA_PRIVATE_KEY ? [process.env.SEPOLIA_PRIVATE_KEY] : [];

export default defineConfig({
  plugins: [hardhatEthers, hardhatVerify],
  solidity: "0.8.24",
  networks: {
    localhost: {
      type: "http",
      chainType: "l1",
      url: localRpcUrl,
      accounts: localAccounts
    },
    ...(sepoliaRpcUrl
      ? {
          sepolia: {
            type: "http",
            chainType: "l1",
            url: sepoliaRpcUrl,
            accounts: sepoliaAccounts
          }
        }
      : {})
  },
  verify: {
    etherscan: {
      apiKey: process.env.ETHERSCAN_API_KEY || ""
    }
  }
});
