import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { HOME_BY_ROLE, ROLES } from "../../config/navigation";
import { useAuth } from "../../context/AuthContext";

const roleOptions = [ROLES.HOLDER, ROLES.ISSUER, ROLES.VERIFIER, ROLES.AUDITOR];

export default function LoginPage() {
  const {
    role,
    setRole,
    walletAddress,
    authError,
    isAuthenticated,
    isAuthenticating,
    loginWithMetaMask,
    clearAuthError
  } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isAuthenticated && role) {
      navigate(HOME_BY_ROLE[role] || "/login", { replace: true });
    }
  }, [isAuthenticated, role, navigate]);

  const onLogin = async () => {
    clearAuthError();
    await loginWithMetaMask(role);
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
        <h2>Login with MetaMask</h2>
        <p className="login-muted">
          Choose your role, then sign the login message in MetaMask to continue.
          Wallet role is locked after first registration.
        </p>

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

        <button
          type="button"
          className="btn btn--primary btn--full"
          disabled={!role || isAuthenticating}
          onClick={onLogin}
        >
          {isAuthenticating ? "Waiting for MetaMask Signature..." : "Login with MetaMask"}
        </button>

        {authError ? <p className="login-error">{authError}</p> : null}
      </section>
    </div>
  );
}
