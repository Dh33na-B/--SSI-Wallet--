import { useState } from "react";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

export default function HolderWalletPage() {
  const { role, walletAddress, walletConnected, loginWithMetaMask, removeMetaMaskAccount } = useAuth();
  const [busy, setBusy] = useState(false);

  const reconnect = async () => {
    setBusy(true);
    try {
      await loginWithMetaMask(role || "HOLDER");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page-stack">
      <PageHeader title="Wallet & Session" subtitle="MetaMask connection and signature status." />

      <SectionCard title="Wallet State">
        <div className="helper-list">
          <p>
            Current Status: <strong>{walletConnected ? "Connected" : "Disconnected"}</strong>
          </p>
          <p>
            Address: <span className="chip">{walletAddress || "No wallet connected"}</span>
          </p>
          <div className="action-row">
            <button type="button" className="btn btn--primary" onClick={reconnect} disabled={busy}>
              {busy ? "Signing..." : "Reconnect MetaMask"}
            </button>
            <button type="button" className="btn btn--ghost">
              Refresh Signature
            </button>
            <button type="button" className="btn btn--danger" onClick={removeMetaMaskAccount}>
              Remove MetaMask Account
            </button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
