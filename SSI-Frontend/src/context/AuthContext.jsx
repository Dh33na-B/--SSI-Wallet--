import { createContext, useContext, useMemo, useState } from "react";

const STORAGE_KEY = "ssi_auth_state";

const readStoredState = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {
        role: "",
        walletAddress: "",
        walletConnected: false
      };
    }
    return JSON.parse(raw);
  } catch {
    return {
      role: "",
      walletAddress: "",
      walletConnected: false
    };
  }
};

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(readStoredState);

  const persist = (next) => {
    setAuth(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
  };

  const setRole = (role) => {
    persist({ ...auth, role });
  };

  const connectWallet = async () => {
    let walletAddress = "";
    if (window.ethereum?.request) {
      const accounts = await window.ethereum.request({
        method: "eth_requestAccounts"
      });
      walletAddress = accounts?.[0] || "";
    }

    if (!walletAddress) {
      const randomTail = Math.random().toString(16).slice(2, 10);
      walletAddress = `0xDEMO${randomTail}`.slice(0, 12);
    }

    persist({
      ...auth,
      walletAddress,
      walletConnected: true
    });
  };

  const disconnectWallet = () => {
    persist({
      role: "",
      walletAddress: "",
      walletConnected: false
    });
  };

  const value = useMemo(
    () => ({
      ...auth,
      setRole,
      connectWallet,
      disconnectWallet
    }),
    [auth]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
