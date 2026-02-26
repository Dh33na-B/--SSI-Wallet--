import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { HOME_BY_ROLE, ROLES } from "../../config/navigation";
import { useAuth } from "../../context/AuthContext";

const roleOptions = [ROLES.HOLDER, ROLES.ISSUER, ROLES.VERIFIER, ROLES.AUDITOR];

export default function LoginPage() {
  const [loading, setLoading] = useState(false);
  const { role, setRole, connectWallet, walletConnected, walletAddress } = useAuth();
  const navigate = useNavigate();

  const canContinue = useMemo(() => walletConnected && role, [walletConnected, role]);

  const onConnect = async () => {
    setLoading(true);
    try {
      await connectWallet();
    } finally {
      setLoading(false);
    }
  };

  const continueToWorkspace = () => {
    navigate(HOME_BY_ROLE[role] || "/login");
  };

  return (
    <div className="login-page">
      <div className="login-hero">
        <h1>Self-Sovereign Identity Workspace</h1>
        <p>
          Role-aware, privacy-first portal for MetaMask authentication, BBS+ selective disclosure,
          encrypted IPFS storage, and Ethereum anchoring.
        </p>
      </div>

      <section className="login-card">
        <h2>Connect Wallet & Choose Role</h2>
        <p className="login-muted">Use MetaMask in production. Demo fallback is enabled for local UI work.</p>

        <button type="button" className="btn btn--primary btn--full" onClick={onConnect} disabled={loading}>
          {walletConnected ? "Wallet Connected" : loading ? "Connecting..." : "Connect MetaMask"}
        </button>

        {walletAddress ? <p className="login-wallet">Active Wallet: {walletAddress}</p> : null}

        <div className="role-grid">
          {roleOptions.map((option) => (
            <button
              key={option}
              type="button"
              className={`role-card ${role === option ? "role-card--active" : ""}`}
              onClick={() => setRole(option)}
            >
              <strong>{option}</strong>
              <span>Open {option.toLowerCase()} workspace</span>
            </button>
          ))}
        </div>

        <button type="button" className="btn btn--secondary btn--full" disabled={!canContinue} onClick={continueToWorkspace}>
          Continue
        </button>
      </section>
    </div>
  );
}
