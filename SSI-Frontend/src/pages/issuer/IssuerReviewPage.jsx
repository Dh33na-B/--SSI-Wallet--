import { base64 } from "@scure/base";
import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";
const IPFS_GATEWAY = import.meta.env.VITE_IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs";

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

export default function IssuerReviewPage() {
  const { documentId } = useParams();
  const navigate = useNavigate();
  const { userId, walletAddress, encryptionPublicKey, refreshAuthSession } = useAuth();

  const [metadata, setMetadata] = useState(null);
  const [access, setAccess] = useState(null);
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [pdfUrl, setPdfUrl] = useState("");

  const getIssuerId = useCallback(async () => {
    let issuerId = userId || "";
    if (!issuerId) {
      issuerId = await refreshAuthSession();
    }
    return issuerId;
  }, [userId, refreshAuthSession]);

  const fetchMetadata = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      return;
    }
    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document metadata."));
    }
    const items = await response.json();
    const target = (Array.isArray(items) ? items : []).find((item) => item.id === documentId) || null;
    setMetadata(target);
  }, [documentId, getIssuerId]);

  const fetchAccess = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      return;
    }
    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents/${documentId}/access`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document access state."));
    }
    const data = await response.json();
    setAccess(data);
    return data;
  }, [documentId, getIssuerId]);

  const requestAccessFromHolder = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      throw new Error("Issuer session not available.");
    }

    const response = await fetch(`${API_BASE_URL}/api/issuer/documents/open`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        issuerId,
        documentId,
        issuerEncryptionPublicKey: encryptionPublicKey || null
      })
    });
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not notify holder."));
    }
    await fetchAccess();
    setMessage("Access request sent to holder. Wait for holder approval, then refresh and decrypt.");
  }, [documentId, encryptionPublicKey, fetchAccess, getIssuerId]);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError("");
      setMessage("");
      try {
        const [, accessState] = await Promise.all([fetchMetadata(), fetchAccess()]);
        if (accessState?.encryptedKey) {
          setMessage("Encrypted key is ready for this issuer. You can decrypt now.");
        } else if (accessState?.reviewStatus === "REQUESTED") {
          setMessage("Waiting for holder approval.");
        }
      } catch (err) {
        setError(err.message || "Could not open review flow.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [fetchAccess, fetchMetadata]);

  useEffect(() => {
    return () => {
      if (pdfUrl) {
        URL.revokeObjectURL(pdfUrl);
      }
    };
  }, [pdfUrl]);

  const decryptDocument = async () => {
    if (!walletAddress) {
      setError("Connect issuer wallet to decrypt document.");
      return;
    }
    if (!access?.encryptedKey) {
      setError("Issuer encrypted key is not available yet. Request holder access first.");
      return;
    }
    if (!access?.ipfsCid || access.ipfsCid === "REMOVED") {
      setError("CID is not available. The document may have been removed.");
      return;
    }
    if (!access?.encryptionIv) {
      setError("Encryption IV is missing.");
      return;
    }

    setDecrypting(true);
    setError("");
    try {
      const keyBase64 = await window.ethereum.request({
        method: "eth_decrypt",
        params: [normalizeEncryptedPayloadForMetaMask(access.encryptedKey), walletAddress]
      });

      const rawKey = base64.decode(keyBase64);
      const iv = base64.decode(access.encryptionIv);
      const aesKey = await window.crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
        "decrypt"
      ]);

      const encryptedResponse = await fetch(`${IPFS_GATEWAY}/${access.ipfsCid}`);
      if (!encryptedResponse.ok) {
        throw new Error("Could not download encrypted document from IPFS.");
      }
      const encryptedBuffer = await encryptedResponse.arrayBuffer();

      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv
        },
        aesKey,
        encryptedBuffer
      );

      if (pdfUrl) {
        URL.revokeObjectURL(pdfUrl);
      }
      const nextUrl = URL.createObjectURL(new Blob([decryptedBuffer], { type: "application/pdf" }));
      setPdfUrl(nextUrl);
      setMessage("Document decrypted successfully. You can now verify and decide.");
    } catch (err) {
      setError(err.message || "Could not decrypt document.");
    } finally {
      setDecrypting(false);
    }
  };

  const submitDecision = async (approved) => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      setError("Issuer session not available.");
      return;
    }

    setLoading(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch(`${API_BASE_URL}/api/issuer/documents/decide`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          issuerId,
          documentId,
          approved,
          reason: reason.trim() || null,
          removePreviousCid: !approved
        })
      });
      if (!response.ok) {
        throw new Error(await normalizeApiError(response, "Could not submit decision."));
      }
      setMessage(
        approved
          ? "Document accepted. Holder has been notified."
          : "Document rejected. Holder notified to re-upload and previous CID removed."
      );
      await Promise.all([fetchMetadata(), fetchAccess()]);
      navigate("/issuer/submissions");
    } catch (err) {
      setError(err.message || "Could not submit decision.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-stack">
      <PageHeader title={`Review ${documentId}`} subtitle="Decrypt document with issuer key access, then decide." />

      <SectionCard title="Document Metadata">
        <div className="helper-list">
          <p>Holder: {metadata?.holderWallet || access?.holderWallet || "-"}</p>
          <p>File: {metadata?.fileName || access?.fileName || "-"}</p>
          <p>Type: {metadata?.documentType || access?.documentType || "-"}</p>
          <p>Document Status: {metadata?.status || "-"}</p>
          <p>Review Request Status: {access?.reviewStatus || metadata?.reviewStatus || "REQUESTED"}</p>
        </div>
      </SectionCard>

      <SectionCard title="Review Access">
        <div className="action-row">
          {!access?.encryptedKey ? (
            <button type="button" className="btn btn--secondary" onClick={requestAccessFromHolder} disabled={loading}>
              Request Holder Access
            </button>
          ) : null}
          <button type="button" className="btn btn--ghost" onClick={fetchAccess} disabled={loading}>
            Refresh Access
          </button>
          <button type="button" className="btn btn--primary" onClick={decryptDocument} disabled={decrypting || loading}>
            {decrypting ? "Decrypting..." : "Decrypt Document"}
          </button>
        </div>
        {message ? <p className="upload-success">{message}</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {pdfUrl ? (
          <div className="pdf-frame-wrap">
            <iframe title="Decrypted Document" src={pdfUrl} className="pdf-frame" />
          </div>
        ) : (
          <p className="login-muted">Decrypted document preview will appear here after key access is available.</p>
        )}
      </SectionCard>

      <SectionCard title="Final Decision">
        <label className="field">
          <span>Reason / Notes</span>
          <textarea
            placeholder="Add verification note or rejection reason..."
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </label>
        <div className="action-row">
          <button type="button" className="btn btn--primary" onClick={() => submitDecision(true)} disabled={loading}>
            Accept
          </button>
          <button type="button" className="btn btn--danger" onClick={() => submitDecision(false)} disabled={loading}>
            Reject & Request Re-upload
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
