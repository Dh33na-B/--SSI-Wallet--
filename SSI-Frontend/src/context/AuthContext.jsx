import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "ssi_auth_state";
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";
const DEFAULT_AUTH_STATE = {
  userId: "",
  role: "",
  walletAddress: "",
  walletConnected: false,
  chainId: "",
  signature: "",
  authMessage: "",
  nonce: "",
  loginAt: "",
  isAuthenticated: false,
  isAuthenticating: false,
  authError: ""
};

const readStoredState = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return DEFAULT_AUTH_STATE;
    }
    return {
      ...DEFAULT_AUTH_STATE,
      ...JSON.parse(raw)
    };
  } catch {
    return DEFAULT_AUTH_STATE;
  }
};

const createNonce = () => {
  if (window.crypto?.getRandomValues) {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  return `${Date.now()}-${Math.random().toString(16).slice(2)}`;
};

const getErrorMessage = (error) => {
  if (error?.code === 4001) {
    return "You rejected the MetaMask request.";
  }
  if (error?.message) {
    return error.message;
  }
  return "MetaMask login failed.";
};

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [auth, setAuth] = useState(readStoredState);

  const persist = useCallback((nextOrUpdater) => {
    setAuth((previous) => {
      const next =
        typeof nextOrUpdater === "function" ? nextOrUpdater(previous) : nextOrUpdater;
      localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const setRole = useCallback(
    (role) => {
      persist((previous) => ({
        ...previous,
        role,
        authError: ""
      }));
    },
    [persist]
  );

  const loginWithMetaMask = useCallback(
    async (selectedRole) => {
      if (!selectedRole) {
        persist((previous) => ({
          ...previous,
          authError: "Select your role before logging in."
        }));
        return;
      }

      if (!window.ethereum?.request) {
        persist((previous) => ({
          ...previous,
          authError: "MetaMask not detected. Install the extension to continue."
        }));
        return;
      }

      persist((previous) => ({
        ...previous,
        isAuthenticating: true,
        authError: ""
      }));

      try {
        const accounts = await window.ethereum.request({
          method: "eth_requestAccounts"
        });
        const walletAddress = accounts?.[0];
        if (!walletAddress) {
          throw new Error("No wallet account selected in MetaMask.");
        }

        const chainId = await window.ethereum.request({
          method: "eth_chainId"
        });
        const nonce = createNonce();
        const issuedAt = new Date().toISOString();

        const message = [
          "Sign in to SSI Workspace",
          `Role: ${selectedRole}`,
          `Wallet: ${walletAddress}`,
          `Nonce: ${nonce}`,
          `Issued At: ${issuedAt}`
        ].join("\n");

        const signature = await window.ethereum.request({
          method: "personal_sign",
          params: [message, walletAddress]
        });

        const response = await fetch(`${API_BASE_URL}/api/auth/metamask/login`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            walletAddress,
            role: selectedRole,
            signature,
            message,
            chainId,
            nonce,
            loginAt: issuedAt
          })
        });

        if (!response.ok) {
          let backendMessage = "Backend login failed.";
          try {
            const errorData = await response.json();
            if (errorData?.message) {
              backendMessage = errorData.message;
            }
          } catch {
            // ignore parse failures and keep default message
          }
          throw new Error(backendMessage);
        }

        const persistedUser = await response.json();
        const backendRole = String(persistedUser.role || "").toUpperCase();
        const uiRole = backendRole === "USER" ? "HOLDER" : backendRole || selectedRole;

        persist({
          userId: persistedUser.userId || "",
          role: uiRole,
          walletAddress: persistedUser.walletAddress || walletAddress,
          walletConnected: true,
          chainId: chainId || "",
          signature: signature || "",
          authMessage: message,
          nonce,
          loginAt: issuedAt,
          isAuthenticated: true,
          isAuthenticating: false,
          authError: ""
        });
      } catch (error) {
        persist((previous) => ({
          ...previous,
          isAuthenticated: false,
          isAuthenticating: false,
          authError: getErrorMessage(error)
        }));
      }
    },
    [persist]
  );

  const clearAuthError = useCallback(() => {
    persist((previous) => ({
      ...previous,
      authError: ""
    }));
  }, [persist]);

  const disconnectWallet = useCallback(() => {
    persist(DEFAULT_AUTH_STATE);
  }, [persist]);

  const removeMetaMaskAccount = useCallback(async () => {
    const walletAddress = auth.walletAddress;

    if (!walletAddress) {
      persist((previous) => ({
        ...previous,
        authError: "No wallet is currently logged in."
      }));
      return;
    }

    const confirmed = window.confirm(
      "This will remove your SSI account from the database and disconnect MetaMask for this site. Continue?"
    );
    if (!confirmed) {
      return;
    }

    persist((previous) => ({
      ...previous,
      isAuthenticating: true,
      authError: ""
    }));

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/metamask/remove-account`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          walletAddress
        })
      });

      if (!response.ok) {
        let backendMessage = "Account removal failed.";
        try {
          const errorData = await response.json();
          if (errorData?.message) {
            backendMessage = errorData.message;
          }
        } catch {
          // ignore parse failures and keep default message
        }
        throw new Error(backendMessage);
      }

      if (window.ethereum?.request) {
        try {
          await window.ethereum.request({
            method: "wallet_revokePermissions",
            params: [{ eth_accounts: {} }]
          });
        } catch {
          // Account was removed in backend already; local logout still proceeds.
        }
      }

      disconnectWallet();
    } catch (error) {
      persist((previous) => ({
        ...previous,
        isAuthenticating: false,
        authError: getErrorMessage(error)
      }));
    }
  }, [auth.walletAddress, disconnectWallet, persist]);

  const refreshAuthSession = useCallback(async () => {
    const current = auth;

    if (
      !current.walletAddress ||
      !current.role ||
      !current.signature ||
      !current.authMessage ||
      !current.nonce
    ) {
      return "";
    }

    persist((previous) => ({
      ...previous,
      isAuthenticating: true,
      authError: ""
    }));

    try {
      const response = await fetch(`${API_BASE_URL}/api/auth/metamask/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          walletAddress: current.walletAddress,
          role: current.role,
          signature: current.signature,
          message: current.authMessage,
          chainId: current.chainId || "",
          nonce: current.nonce,
          loginAt: current.loginAt || new Date().toISOString()
        })
      });

      if (!response.ok) {
        let backendMessage = "Session refresh failed.";
        try {
          const errorData = await response.json();
          if (errorData?.message) {
            backendMessage = errorData.message;
          }
        } catch {
          // ignore parse failures and keep default message
        }
        throw new Error(backendMessage);
      }

      const persistedUser = await response.json();
      const backendRole = String(persistedUser.role || "").toUpperCase();
      const uiRole = backendRole === "USER" ? "HOLDER" : backendRole || current.role;
      const refreshedUserId = persistedUser.userId || current.userId || "";

      persist((previous) => ({
        ...previous,
        userId: refreshedUserId,
        role: uiRole,
        walletAddress: persistedUser.walletAddress || previous.walletAddress,
        walletConnected: true,
        isAuthenticated: true,
        isAuthenticating: false,
        authError: ""
      }));

      return refreshedUserId;
    } catch (error) {
      persist((previous) => ({
        ...previous,
        isAuthenticating: false,
        authError: getErrorMessage(error)
      }));
      return "";
    }
  }, [auth, persist]);

  useEffect(() => {
    if (!window.ethereum?.on) {
      return undefined;
    }

    const handleAccountsChanged = (accounts) => {
      const current = accounts?.[0];

      if (!current) {
        disconnectWallet();
        return;
      }

      persist((previous) => {
        if (!previous.walletAddress) {
          return previous;
        }
        if (previous.walletAddress.toLowerCase() !== current.toLowerCase()) {
          return {
            ...DEFAULT_AUTH_STATE,
            authError: "Wallet account changed. Please login again."
          };
        }
        return {
          ...previous,
          walletAddress: current,
          walletConnected: true
        };
      });
    };

    const handleChainChanged = (chainId) => {
      persist((previous) => ({
        ...previous,
        chainId: chainId || previous.chainId
      }));
    };

    window.ethereum.on("accountsChanged", handleAccountsChanged);
    window.ethereum.on("chainChanged", handleChainChanged);

    return () => {
      if (!window.ethereum?.removeListener) {
        return;
      }
      window.ethereum.removeListener("accountsChanged", handleAccountsChanged);
      window.ethereum.removeListener("chainChanged", handleChainChanged);
    };
  }, [disconnectWallet, persist]);

  const value = useMemo(
    () => ({
      ...auth,
      setRole,
      loginWithMetaMask,
      refreshAuthSession,
      clearAuthError,
      disconnectWallet,
      removeMetaMaskAccount
    }),
    [
      auth,
      setRole,
      loginWithMetaMask,
      refreshAuthSession,
      clearAuthError,
      disconnectWallet,
      removeMetaMaskAccount
    ]
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
