import { base64 } from "@scure/base";
import { useCallback, useEffect, useMemo, useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";
const BBS_SIGNER_BASE_URL = import.meta.env.VITE_BBS_SIGNER_BASE_URL || "http://localhost:8085";
const BBS_SIGNER_AUTH_TOKEN = import.meta.env.VITE_BBS_SIGNER_AUTH_TOKEN || "";
const IPFS_GATEWAY_BASE =
  import.meta.env.VITE_IPFS_GATEWAY_BASE || "https://gateway.pinata.cloud/ipfs";

const parseApiError = async (response, fallback) => {
  try {
    const data = await response.json();
    if (data?.message) {
      return data.message;
    }
  } catch {
    // ignore
  }
  return fallback;
};

const normalizeClientError = (error, fallback = "Request failed.") => {
  const message = String(error?.message || "").trim();
  const lowered = message.toLowerCase();

  if (
    error?.code === 4001 ||
    lowered.includes("user denied message decryption") ||
    lowered.includes("metamask decryptmessage: user denied")
  ) {
    return "MetaMask decryption was denied. Click Review & Share again and approve the decrypt popup.";
  }
  if (lowered.includes("expected 112-byte bbs signature") || lowered.includes("invalid size of signature")) {
    return "This VC does not contain a valid issuer BBS signature. Re-issue this credential from issuer side and retry.";
  }
  if (lowered.includes("derived proof, not an issuer signature")) {
    return "This VC payload already contains a derived proof, not an issuer signature. Re-issue the VC and retry.";
  }
  if (lowered.includes("bbs signer unauthorized") || lowered === "unauthorized") {
    return "BBS signer authorization failed. Restart services so backend/signer/frontend share the same BBS_SIGNER_AUTH_TOKEN.";
  }
  return message || fallback;
};

const formatDateTime = (value) => (value ? new Date(value).toLocaleString() : "-");
const short = (value) => (value && value.length > 22 ? `${value.slice(0, 10)}...${value.slice(-8)}` : value || "-");

const normalizeEncryptedPayloadForMetaMask = (value) => {
  if (typeof value !== "string") {
    return value;
  }
  const trimmed = value.trim();
  if (trimmed.startsWith("0x")) {
    return trimmed;
  }
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const bytes = new TextEncoder().encode(trimmed);
    return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
  return trimmed;
};

const decryptEncryptedVc = async (encryptedBlob, keyBase64) => {
  const blob = encryptedBlob instanceof Uint8Array ? encryptedBlob : new Uint8Array(encryptedBlob);
  if (blob.length <= 12) {
    throw new Error("Encrypted VC payload is invalid.");
  }

  const keyBytes = base64.decode(keyBase64);
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const cryptoKey = await window.crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "decrypt"
  ]);
  const plaintext = await window.crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv
    },
    cryptoKey,
    ciphertext
  );
  const signedCredentialText = new TextDecoder().decode(new Uint8Array(plaintext));
  return JSON.parse(signedCredentialText);
};

const validateDecryptedVcKey = (rawKeyValue) => {
  const keyValue = String(rawKeyValue || "").trim();
  if (!keyValue) {
    throw new Error("Decrypted VC key is empty.");
  }
  let decoded = null;
  try {
    decoded = base64.decode(keyValue);
  } catch {
    throw new Error(
      "Decrypted VC key is not valid base64. This credential was issued with an incompatible key envelope. Re-issue the credential."
    );
  }
  if (!(decoded instanceof Uint8Array) || decoded.length !== 32) {
    throw new Error(
      `Decrypted VC key length is ${decoded?.length || 0} bytes. Expected 32-byte AES-256 key. Re-issue the credential.`
    );
  }
  return keyValue;
};

const fetchEncryptedVcFromIpfs = async (cid) => {
  const cleanCid = String(cid || "").trim();
  if (!cleanCid) {
    throw new Error("Credential CID is missing.");
  }
  const response = await fetch(`${IPFS_GATEWAY_BASE}/${cleanCid}`);
  if (!response.ok) {
    throw new Error("Could not fetch encrypted VC from IPFS.");
  }
  return new Uint8Array(await response.arrayBuffer());
};

const getActiveWallet = async () => {
  if (!window.ethereum?.request) {
    throw new Error("MetaMask is required.");
  }
  let accounts = await window.ethereum.request({ method: "eth_accounts" });
  if (!accounts || accounts.length === 0) {
    accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
  }
  const activeWallet = accounts?.[0];
  if (!activeWallet) {
    throw new Error("No MetaMask account selected.");
  }
  return activeWallet;
};

const deriveProofOnHolderSide = async (signedCredential, selectedFields) => {
  const headers = {
    "Content-Type": "application/json"
  };
  if (BBS_SIGNER_AUTH_TOKEN) {
    headers.Authorization = `Bearer ${BBS_SIGNER_AUTH_TOKEN}`;
  }

  const response = await fetch(`${BBS_SIGNER_BASE_URL}/v1/credentials/proof`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      signedCredential,
      revealFields: selectedFields
    })
  });
  if (!response.ok) {
    throw new Error(await parseApiError(response, "Could not generate BBS+ selective proof."));
  }
  return response.json();
};

const ensureDerivableSignedCredential = (signedCredential) => {
  const proof = signedCredential?.proof;
  if (!proof || typeof proof !== "object") {
    throw new Error("Credential payload is missing issuer signature proof.");
  }
  const type = String(proof.type || "").trim();
  if (type === "BbsBlsSignatureProof2020") {
    throw new Error("Credential payload contains a derived proof, not issuer signature.");
  }
  if (!proof.proofValue || typeof proof.proofValue !== "string") {
    throw new Error("Credential payload proofValue is missing.");
  }
};

export default function HolderProofRequestsPage() {
  const { userId, walletAddress, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [modal, setModal] = useState({
    open: false,
    request: null,
    selectedFields: [],
    signedCredential: null,
    loadingCredential: false,
    submitting: false
  });

  const resolveHolderId = useCallback(async () => {
    let holderId = userId || "";
    if (!holderId) {
      holderId = await refreshAuthSession();
    }
    return holderId;
  }, [refreshAuthSession, userId]);

  const fetchRequests = useCallback(async () => {
    const holderId = await resolveHolderId();
    if (!holderId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/holder/${holderId}/proof-requests`);
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not load proof requests."));
    }

    const data = await response.json();
    setRows(
      (Array.isArray(data) ? data : []).map((item) => ({
        id: item.requestId,
        requestId: item.requestId,
        credentialId: item.credentialId,
        verifierWallet: item.verifierWallet || "-",
        requestedFields: Array.isArray(item.requestedFields) ? item.requestedFields : [],
        disclosedFields: Array.isArray(item.disclosedFields) ? item.disclosedFields : [],
        status: item.status || "-",
        verification: item.verificationStatus ? "VALID" : item.verificationStatus === false ? "INVALID" : "PENDING",
        createdAt: formatDateTime(item.createdAt),
        respondedAt: formatDateTime(item.respondedAt),
        verifiedAt: formatDateTime(item.verifiedAt)
      }))
    );
  }, [resolveHolderId]);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError("");
      try {
        await fetchRequests();
      } catch (err) {
        setError(err.message || "Could not load proof requests.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [fetchRequests]);

  const loadSignedCredential = async (requestRow) => {
    const holderId = await resolveHolderId();
    if (!holderId) {
      throw new Error("Holder session not available.");
    }

    const response = await fetch(
      `${API_BASE_URL}/api/holder/${holderId}/credentials/${requestRow.credentialId}/access`
    );
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not fetch credential access details."));
    }
    const access = await response.json();

    const activeWallet = await getActiveWallet();
    if (walletAddress && walletAddress.toLowerCase() !== activeWallet.toLowerCase()) {
      throw new Error(`Selected MetaMask account does not match logged-in holder (${walletAddress}).`);
    }

    const keyBase64 = await window.ethereum.request({
      method: "eth_decrypt",
      params: [normalizeEncryptedPayloadForMetaMask(access.encryptedKey), activeWallet]
    });
    const validatedKeyBase64 = validateDecryptedVcKey(keyBase64);

    const encryptedVc = await fetchEncryptedVcFromIpfs(access.vcIpfsCid);
    return decryptEncryptedVc(encryptedVc, validatedKeyBase64);
  };

  const openRequestModal = async (row) => {
    setModal({
      open: true,
      request: row,
      selectedFields: row.requestedFields,
      signedCredential: null,
      loadingCredential: true,
      submitting: false
    });
    setError("");
    setMessage("");

    try {
      const signedCredential = await loadSignedCredential(row);
      ensureDerivableSignedCredential(signedCredential);
      setModal((prev) => ({ ...prev, signedCredential, loadingCredential: false }));
    } catch (err) {
      setModal((prev) => ({ ...prev, loadingCredential: false }));
      setError(normalizeClientError(err, "Could not decrypt and load signed credential."));
    }
  };

  const closeModal = () => {
    setModal({
      open: false,
      request: null,
      selectedFields: [],
      signedCredential: null,
      loadingCredential: false,
      submitting: false
    });
  };

  const submitDecision = async (decline = false) => {
    const requestRow = modal.request;
    if (!requestRow) {
      return;
    }

    const holderId = await resolveHolderId();
    if (!holderId) {
      setError("Holder session not available.");
      return;
    }

    setModal((prev) => ({ ...prev, submitting: true }));
    setError("");
    setMessage("");

    try {
      let payload = {
        holderId,
        requestId: requestRow.requestId,
        disclosedFields: [],
        signedCredential: null,
        proofValue: null,
        proofNonce: null,
        revealedClaims: null,
        revealedMessages: []
      };
      let derivedOnHolder = false;

      if (!decline) {
        if (!modal.signedCredential) {
          throw new Error("Signed credential is not loaded yet.");
        }
        if (!modal.selectedFields || modal.selectedFields.length === 0) {
          throw new Error("Select at least one field or click Decline.");
        }

        let proof = null;
        try {
          proof = await deriveProofOnHolderSide(modal.signedCredential, modal.selectedFields);
          derivedOnHolder = true;
        } catch (proofErr) {
          const deriveMessage = String(proofErr?.message || "").toLowerCase();
          if (
            deriveMessage.includes("signature") ||
            deriveMessage.includes("derived proof") ||
            deriveMessage.includes("proofvalue")
          ) {
            throw proofErr;
          }
          // Fallback: backend derives proof using signer service if frontend signer access is blocked.
        }
        payload = {
          holderId,
          requestId: requestRow.requestId,
          disclosedFields: modal.selectedFields,
          signedCredential: modal.signedCredential,
          proofValue: proof?.proofValue || null,
          proofNonce: proof?.nonce || null,
          revealedClaims: proof?.revealedClaims || null,
          revealedMessages: Array.isArray(proof?.revealedMessages) ? proof.revealedMessages : []
        };
      }

      const response = await fetch(`${API_BASE_URL}/api/holder/proof/share`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
      });
      if (!response.ok) {
        throw new Error(await parseApiError(response, "Could not submit selective proof response."));
      }

      await fetchRequests();
      setMessage(
        decline
          ? "Proof request declined."
          : derivedOnHolder
            ? "Selective disclosure proof generated on holder side and submitted to verifier."
            : "Selected attributes submitted. Backend generated/verified proof because frontend signer access was unavailable."
      );
      closeModal();
    } catch (err) {
      setError(normalizeClientError(err, "Could not submit proof response."));
      setModal((prev) => ({ ...prev, submitting: false }));
    }
  };

  const columns = useMemo(
    () => [
      { key: "requestId", header: "Request ID", render: (value) => short(value) },
      { key: "credentialId", header: "Credential ID" },
      { key: "verifierWallet", header: "Verifier", render: (value) => short(value) },
      {
        key: "requestedFields",
        header: "Requested Fields",
        render: (value) => (Array.isArray(value) && value.length > 0 ? value.join(", ") : "-")
      },
      { key: "status", header: "Request Status", render: (value) => <Badge value={value} /> },
      { key: "verification", header: "Verification", render: (value) => <Badge value={value} /> },
      { key: "createdAt", header: "Requested At" },
      { key: "respondedAt", header: "Responded At" },
      {
        key: "action",
        header: "Action",
        render: (_, row) =>
          row.status === "REQUESTED" ? (
            <button type="button" className="btn btn--secondary" onClick={() => openRequestModal(row)}>
              Review & Share
            </button>
          ) : (
            <span className="login-muted">Completed</span>
          )
      }
    ],
    []
  );

  return (
    <div className="page-stack">
      <PageHeader
        title="Verification Requests"
        subtitle="Review verifier requests, choose fields, generate BBS+ selective proof, and submit."
      />

      <SectionCard title="Incoming Proof Requests">
        {loading ? <p className="login-muted">Loading proof requests...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {message ? <p className="upload-success">{message}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>

      <Modal
        open={modal.open}
        title="Review Proof Request"
        onClose={closeModal}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={closeModal} disabled={modal.submitting}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn--danger"
              onClick={() => submitDecision(true)}
              disabled={modal.submitting}
            >
              Decline
            </button>
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => submitDecision(false)}
              disabled={modal.submitting || modal.loadingCredential}
            >
              Generate & Share Proof
            </button>
          </>
        }
      >
        <p>
          Request ID: <strong>{modal.request?.requestId || "-"}</strong>
        </p>
        <p>
          Verifier: <strong>{modal.request?.verifierWallet || "-"}</strong>
        </p>
        <p>
          Credential: <strong>{modal.request?.credentialId || "-"}</strong>
        </p>
        <p>
          Status: <Badge value={modal.request?.status || "-"} />
        </p>

        <label className="field">
          <span>Select fields to disclose</span>
          <div className="field-grid">
            {(modal.request?.requestedFields || []).map((field) => (
              <label key={field} className="field-chip">
                <input
                  type="checkbox"
                  checked={modal.selectedFields.includes(field)}
                  onChange={() =>
                    setModal((prev) => ({
                      ...prev,
                      selectedFields: prev.selectedFields.includes(field)
                        ? prev.selectedFields.filter((value) => value !== field)
                        : [...prev.selectedFields, field]
                    }))
                  }
                />
                <span>{field}</span>
              </label>
            ))}
          </div>
        </label>

        {modal.loadingCredential ? (
          <p className="login-muted">
            Decrypting VC key with MetaMask and loading signed credential from IPFS...
          </p>
        ) : (
          <p className="field-help">
            Proof generation runs on the holder side using your signed VC and selected attributes only.
          </p>
        )}
      </Modal>
    </div>
  );
}
