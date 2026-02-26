import { base64, utf8 } from "@scure/base";
import { useCallback, useEffect, useState } from "react";
import nacl from "tweetnacl";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

const normalizeApiError = async (response, fallbackMessage) => {
  let message = fallbackMessage;
  try {
    const data = await response.json();
    if (data?.message) {
      message = data.message;
    }
  } catch {
    // ignore parse errors
  }
  return message;
};

const shortText = (value, max = 20) => {
  if (!value) {
    return "-";
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
};

const formatDateTime = (value) => {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
};

const bytesToHex = (bytes) =>
  `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

const utf8ToHex = (value) => bytesToHex(new TextEncoder().encode(value));

const normalizeEncryptedPayloadForMetaMask = (value) => {
  if (typeof value !== "string") {
    return value;
  }
  const trimmed = value.trim();
  if (trimmed.startsWith("0x")) {
    return trimmed;
  }
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    return utf8ToHex(trimmed);
  }
  return value;
};

const normalizeWalletError = (error) => {
  const message = String(error?.message || "");
  const lowered = message.toLowerCase();

  if (error?.code === 4001 || lowered.includes("user denied message decryption")) {
    return "MetaMask decrypt was canceled. Click Accept again and approve the 'Decrypt message' popup.";
  }
  if (lowered.includes("wallet account does not match")) {
    return message;
  }
  if (lowered.includes("metamask")) {
    return message;
  }
  return message || "Failed to submit response.";
};

export default function HolderProofRequestsPage() {
  const { userId, walletAddress, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [decisionModal, setDecisionModal] = useState({
    open: false,
    request: null,
    action: "",
    note: "",
    submitting: false
  });

  const fetchRequests = useCallback(async () => {
    let holderId = userId || "";
    if (!holderId) {
      holderId = await refreshAuthSession();
    }
    if (!holderId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/holder/${holderId}/review-requests`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load review notifications."));
    }
    const data = await response.json();
    setRows(Array.isArray(data) ? data : []);
  }, [userId, refreshAuthSession]);

  useEffect(() => {
    const run = async () => {
      setIsLoading(true);
      setError("");
      try {
        await fetchRequests();
      } catch (err) {
        setError(err.message || "Failed to load review notifications.");
      } finally {
        setIsLoading(false);
      }
    };
    run();
  }, [fetchRequests]);

  const encryptForIssuer = (issuerPublicKey, keyBase64) => {
    const publicKeyBytes = base64.decode(issuerPublicKey);
    const ephemeralKeyPair = nacl.box.keyPair();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const messageBytes = utf8.decode(keyBase64);
    const ciphertext = nacl.box(messageBytes, nonce, publicKeyBytes, ephemeralKeyPair.secretKey);

    return utf8ToHex(JSON.stringify({
      version: "x25519-xsalsa20-poly1305",
      nonce: base64.encode(nonce),
      ephemPublicKey: base64.encode(ephemeralKeyPair.publicKey),
      ciphertext: base64.encode(ciphertext)
    }));
  };

  const submitDecision = async () => {
    const selected = decisionModal.request;
    if (!selected) {
      return;
    }

    let holderId = userId || "";
    if (!holderId) {
      holderId = await refreshAuthSession();
    }
    if (!holderId) {
      setError("Holder session not available.");
      return;
    }

    const approved = decisionModal.action === "ACCEPT";

    setDecisionModal((previous) => ({ ...previous, submitting: true }));
    setError("");
    setMessage("");

    try {
      let encryptedKeyForIssuer = null;

      if (approved) {
        if (!window.ethereum?.request) {
          throw new Error("MetaMask is required to approve verification access.");
        }
        if (!walletAddress) {
          throw new Error("Connect your wallet to approve document verification.");
        }
        if (!selected.holderEncryptedKey) {
          throw new Error("Holder encrypted key not found for this document.");
        }
        if (!selected.issuerEncryptionPublicKey) {
          throw new Error("Issuer encryption public key not available. Ask issuer to login again.");
        }

        let connectedAccounts = await window.ethereum.request({
          method: "eth_accounts"
        });
        let activeWallet = connectedAccounts?.[0] || "";
        if (!activeWallet) {
          connectedAccounts = await window.ethereum.request({
            method: "eth_requestAccounts"
          });
          activeWallet = connectedAccounts?.[0] || "";
        }
        if (!activeWallet) {
          throw new Error("No MetaMask account selected.");
        }
        if (walletAddress.toLowerCase() !== activeWallet.toLowerCase()) {
          throw new Error(
            `Selected MetaMask account does not match the logged-in holder account (${walletAddress}).`
          );
        }

        const keyBase64 = await window.ethereum.request({
          method: "eth_decrypt",
          params: [normalizeEncryptedPayloadForMetaMask(selected.holderEncryptedKey), activeWallet]
        });

        encryptedKeyForIssuer = encryptForIssuer(selected.issuerEncryptionPublicKey, keyBase64);
      }

      const response = await fetch(`${API_BASE_URL}/api/holder/review-requests/respond`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          holderId,
          requestId: selected.requestId,
          approved,
          encryptedKeyForIssuer,
          note: decisionModal.note.trim() || null
        })
      });

      if (!response.ok) {
        throw new Error(await normalizeApiError(response, "Could not submit review response."));
      }

      await fetchRequests();
      setMessage(
        approved
          ? "Access approved. Requester can now decrypt and view the document."
          : "Request rejected."
      );
      setDecisionModal({ open: false, request: null, action: "", note: "", submitting: false });
    } catch (err) {
      setDecisionModal((previous) => ({ ...previous, submitting: false }));
      setError(normalizeWalletError(err));
    }
  };

  const columns = [
    { key: "requestId", header: "Request ID", render: (value) => shortText(value, 22) },
    { key: "issuerWallet", header: "Requester Wallet", render: (value) => shortText(value, 22) },
    { key: "fileName", header: "File Name", render: (value) => value || "-" },
    { key: "documentType", header: "Type", render: (value) => value || "-" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    { key: "updatedAt", header: "Updated", render: (value) => formatDateTime(value) },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) => {
        if (row.status !== "REQUESTED") {
          return <span className="login-muted">No action</span>;
        }
        return (
          <div className="action-row">
            <button
              type="button"
              className="btn btn--secondary"
              onClick={() =>
                setDecisionModal({ open: true, request: row, action: "ACCEPT", note: "", submitting: false })
              }
            >
              Accept
            </button>
            <button
              type="button"
              className="btn btn--danger"
              onClick={() =>
                setDecisionModal({ open: true, request: row, action: "REJECT", note: "", submitting: false })
              }
            >
              Reject
            </button>
          </div>
        );
      }
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader
        title="Document Access Approvals"
        subtitle="Approve a request, confirm in MetaMask, then requester can decrypt for verification."
      />

      <SectionCard title="Incoming Verification Requests">
        <p className="field-help">
          When you click <strong>Accept</strong>, MetaMask will ask you to decrypt the document key. Approve that popup
          to grant access.
        </p>
        {isLoading ? <p className="login-muted">Loading notifications...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {message ? <p className="upload-success">{message}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>

      <Modal
        open={decisionModal.open}
        title={`${decisionModal.action} Access Request`}
        onClose={() => setDecisionModal({ open: false, request: null, action: "", note: "", submitting: false })}
        footer={
          <>
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() =>
                setDecisionModal({ open: false, request: null, action: "", note: "", submitting: false })
              }
            >
              Cancel
            </button>
            <button
              type="button"
              className={decisionModal.action === "ACCEPT" ? "btn btn--primary" : "btn btn--danger"}
              onClick={submitDecision}
              disabled={decisionModal.submitting}
            >
              Confirm {decisionModal.action}
            </button>
          </>
        }
      >
        <p>
          Request: <strong>{decisionModal.request?.requestId}</strong>
        </p>
        <p>
          Requester: <strong>{decisionModal.request?.issuerWallet || "-"}</strong>
        </p>
        <label className="field">
          <span>Note (Optional)</span>
          <textarea
            placeholder="Add a note for issuer/audit trail..."
            value={decisionModal.note}
            onChange={(event) =>
              setDecisionModal((previous) => ({
                ...previous,
                note: event.target.value
              }))
            }
          />
        </label>
      </Modal>
    </div>
  );
}
