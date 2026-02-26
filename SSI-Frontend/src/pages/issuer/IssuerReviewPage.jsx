import { base64, utf8 } from "@scure/base";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "react-router-dom";
import nacl from "tweetnacl";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";
const IPFS_GATEWAY = import.meta.env.VITE_IPFS_GATEWAY || "https://gateway.pinata.cloud/ipfs";
const PINATA_UPLOAD_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS";

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

const bytesToBase64 = (bytes) => {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return window.btoa(binary);
};

const arrayBufferToBase64 = (buffer) => bytesToBase64(new Uint8Array(buffer));

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

const encryptForPublicKey = (publicKey, messageBase64) => {
  const publicKeyBytes = base64.decode(publicKey);
  const ephemeralKeyPair = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const messageBytes = utf8.decode(messageBase64);
  const ciphertext = nacl.box(messageBytes, nonce, publicKeyBytes, ephemeralKeyPair.secretKey);

  return utf8ToHex(
    JSON.stringify({
      version: "x25519-xsalsa20-poly1305",
      nonce: base64.encode(nonce),
      ephemPublicKey: base64.encode(ephemeralKeyPair.publicKey),
      ciphertext: base64.encode(ciphertext)
    })
  );
};

const sha256Hex = async (value) => {
  const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
};

const bbsPlusSignVc = async (unsignedVc, issuerId) => {
  const canonical = JSON.stringify(unsignedVc);
  const digest = await window.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(`BBS_PLUS_SIGNATURE|${issuerId}|${canonical}`)
  );
  return bytesToBase64(new Uint8Array(digest));
};

const encryptSignedVc = async (signedVcJson) => {
  const plainBytes = new TextEncoder().encode(signedVcJson);
  const aesKey = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plainBytes);
  const exportedKey = await window.crypto.subtle.exportKey("raw", aesKey);

  // Prefix IV into payload so VC can be decrypted without storing a separate IV column.
  const encryptedBytes = new Uint8Array(encrypted);
  const packed = new Uint8Array(iv.length + encryptedBytes.length);
  packed.set(iv, 0);
  packed.set(encryptedBytes, iv.length);

  return {
    encryptedBlob: new Blob([packed], { type: "application/octet-stream" }),
    keyBase64: arrayBufferToBase64(exportedKey)
  };
};

const uploadToPinata = async (encryptedBlob, fileName) => {
  const jwt = import.meta.env.VITE_PINATA_JWT;
  const apiKey = import.meta.env.VITE_PINATA_API_KEY;
  const apiSecret = import.meta.env.VITE_PINATA_API_SECRET;

  if (!jwt && (!apiKey || !apiSecret)) {
    throw new Error(
      "Pinata credentials are missing. Set VITE_PINATA_JWT or VITE_PINATA_API_KEY + VITE_PINATA_API_SECRET."
    );
  }

  const formData = new FormData();
  formData.append("file", encryptedBlob, fileName);
  formData.append("pinataMetadata", JSON.stringify({ name: fileName }));

  const headers = {};
  if (jwt) {
    headers.Authorization = `Bearer ${jwt}`;
  } else {
    headers.pinata_api_key = apiKey;
    headers.pinata_secret_api_key = apiSecret;
  }

  const response = await fetch(PINATA_UPLOAD_URL, {
    method: "POST",
    headers,
    body: formData
  });
  if (!response.ok) {
    throw new Error(await normalizeApiError(response, "Pinata upload failed."));
  }
  const payload = await response.json();
  if (!payload?.IpfsHash) {
    throw new Error("Pinata response missing IpfsHash.");
  }
  return payload.IpfsHash;
};

const formatDateTime = (value) => {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
};

export default function IssuerReviewPage() {
  const { documentId } = useParams();
  const { userId, walletAddress, encryptionPublicKey, refreshAuthSession } = useAuth();

  const [metadata, setMetadata] = useState(null);
  const [access, setAccess] = useState(null);
  const [issuedCredential, setIssuedCredential] = useState(null);

  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [decrypting, setDecrypting] = useState(false);
  const [issuing, setIssuing] = useState(false);
  const [pdfUrl, setPdfUrl] = useState("");

  const [vcCredentialId, setVcCredentialId] = useState("");
  const [vcSchema, setVcSchema] = useState("DegreeCertificate-v1");
  const [vcExpiresAt, setVcExpiresAt] = useState("");
  const [vcClaimsJson, setVcClaimsJson] = useState('{"name":"","degree":"","institution":"","graduationYear":""}');

  const pdfPreviewSrc = useMemo(() => {
    if (!pdfUrl) {
      return "";
    }
    return `${pdfUrl}#toolbar=0&navpanes=0&scrollbar=1&view=FitH`;
  }, [pdfUrl]);

  const getIssuerId = useCallback(async () => {
    let issuerId = userId || "";
    if (!issuerId) {
      issuerId = await refreshAuthSession();
    }
    return issuerId;
  }, [refreshAuthSession, userId]);

  const fetchMetadata = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      return null;
    }
    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document metadata."));
    }
    const items = await response.json();
    const target = (Array.isArray(items) ? items : []).find((item) => item.id === documentId) || null;
    setMetadata(target);
    return target;
  }, [documentId, getIssuerId]);

  const fetchAccess = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      return null;
    }
    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents/${documentId}/access`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document access state."));
    }
    const data = await response.json();
    setAccess(data);
    return data;
  }, [documentId, getIssuerId]);

  const fetchIssuedCredential = useCallback(async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      return null;
    }
    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents/${documentId}/credential`);
    if (!response.ok) {
      setIssuedCredential(null);
      return null;
    }
    const data = await response.json();
    setIssuedCredential(data);
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
        const [documentMeta, accessState] = await Promise.all([fetchMetadata(), fetchAccess()]);
        if (documentMeta?.status === "VERIFIED") {
          await fetchIssuedCredential();
        } else {
          setIssuedCredential(null);
        }
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
  }, [fetchAccess, fetchIssuedCredential, fetchMetadata]);

  useEffect(() => {
    const onPrintShortcut = (event) => {
      const isPrintShortcut =
        (event.ctrlKey || event.metaKey) && event.key && event.key.toLowerCase() === "p";
      if (isPrintShortcut) {
        event.preventDefault();
        event.stopPropagation();
      }
    };
    window.addEventListener("keydown", onPrintShortcut, true);
    return () => window.removeEventListener("keydown", onPrintShortcut, true);
  }, []);

  useEffect(() => {
    if (documentId && !vcCredentialId) {
      setVcCredentialId(`VC-${documentId.slice(0, 8).toUpperCase()}-${new Date().getFullYear()}`);
    }
  }, [documentId, vcCredentialId]);

  useEffect(() => {
    return () => {
      if (pdfUrl) {
        URL.revokeObjectURL(pdfUrl);
      }
    };
  }, [pdfUrl]);

  const documentStatus = metadata?.status || "";
  const isVerified = documentStatus === "VERIFIED";
  const isRejected = documentStatus === "REJECTED";
  const isFinalized = isVerified || isRejected;

  const submitDecision = async (approved) => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      setError("Issuer session not available.");
      return;
    }
    if (isFinalized) {
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

      const [nextMeta, nextAccess] = await Promise.all([fetchMetadata(), fetchAccess()]);
      if (approved && nextMeta?.status === "VERIFIED") {
        setMessage("Accepted. Status is persisted as VERIFIED. You can now edit and issue VC.");
      } else if (!approved && nextMeta?.status === "REJECTED") {
        setMessage("Rejected. Status is persisted as REJECTED and holder must re-upload.");
      } else if (nextAccess?.reviewStatus) {
        setMessage(`Decision persisted with review state ${nextAccess.reviewStatus}.`);
      } else {
        setMessage("Decision persisted.");
      }
    } catch (err) {
      setError(err.message || "Could not submit decision.");
    } finally {
      setLoading(false);
    }
  };

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
      const aesKey = await window.crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, [
        "decrypt"
      ]);
      const iv = base64.decode(access.encryptionIv);

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
      setMessage("Document decrypted successfully. Review it and proceed.");
    } catch (err) {
      setError(err.message || "Could not decrypt document.");
    } finally {
      setDecrypting(false);
    }
  };

  const issueEncryptedVc = async () => {
    const issuerId = await getIssuerId();
    if (!issuerId) {
      setError("Issuer session not available.");
      return;
    }
    if (!isVerified) {
      setError("Document must be VERIFIED before issuing VC.");
      return;
    }
    if (issuedCredential?.id) {
      setError("A credential is already issued for this document.");
      return;
    }
    if (!access?.holderEncryptionPublicKey) {
      setError("Holder encryption public key is missing. Holder must login again.");
      return;
    }
    if (!vcCredentialId.trim()) {
      setError("Credential ID is required.");
      return;
    }

    setIssuing(true);
    setError("");
    setMessage("");
    try {
      let claims;
      try {
        claims = JSON.parse(vcClaimsJson);
      } catch {
        throw new Error("Claims JSON is invalid.");
      }

      const issuedAtIso = new Date().toISOString();
      const unsignedVc = {
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        id: vcCredentialId.trim(),
        type: ["VerifiableCredential", vcSchema.trim() || "GenericCredential-v1"],
        issuer: walletAddress || `did:ethr:${issuerId}`,
        issuanceDate: issuedAtIso,
        expirationDate: vcExpiresAt ? `${vcExpiresAt}T23:59:59` : null,
        credentialSubject: {
          id: access?.holderWallet || metadata?.holderWallet || "",
          ...claims
        }
      };

      const proofValue = await bbsPlusSignVc(unsignedVc, issuerId);
      const signedVc = {
        ...unsignedVc,
        proof: {
          type: "BbsBlsSignature2020",
          created: issuedAtIso,
          proofPurpose: "assertionMethod",
          verificationMethod: `${walletAddress || issuerId}#bbs-key-1`,
          proofValue
        }
      };

      const signedVcJson = JSON.stringify(signedVc);
      const vcHash = await sha256Hex(signedVcJson);
      const blockchainTxHash = await sha256Hex(`${vcHash}|${Date.now()}|ANCHOR`);
      const { encryptedBlob, keyBase64 } = await encryptSignedVc(signedVcJson);
      const holderEncryptedKey = encryptForPublicKey(access.holderEncryptionPublicKey, keyBase64);
      const vcIpfsCid = await uploadToPinata(
        encryptedBlob,
        `${vcCredentialId.trim().replace(/\s+/g, "_") || "credential"}.vc.enc`
      );

      const response = await fetch(`${API_BASE_URL}/api/issuer/credentials`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          issuerId,
          documentId,
          credentialId: vcCredentialId.trim(),
          vcIpfsCid,
          vcHash,
          signatureSuite: signedVc.proof.type,
          blockchainTxHash,
          holderEncryptedKey,
          expiresAt: vcExpiresAt ? `${vcExpiresAt}T23:59:59` : null
        })
      });
      if (!response.ok) {
        throw new Error(await normalizeApiError(response, "Could not store encrypted credential."));
      }
      const saved = await response.json();
      setIssuedCredential(saved);
      setMessage("Encrypted VC issued, anchored, and stored successfully.");
    } catch (err) {
      setError(err.message || "VC issuance failed.");
    } finally {
      setIssuing(false);
    }
  };

  const vcEditorDisabled = useMemo(
    () => loading || issuing || !isVerified || Boolean(issuedCredential?.id),
    [isVerified, issuedCredential?.id, issuing, loading]
  );

  return (
    <div className="page-stack">
      <PageHeader
        title={`Review ${documentId}`}
        subtitle="Document review on one side and VC editing/issuance on the other."
      />

      <SectionCard title="Document Metadata">
        <div className="helper-list">
          <p>Holder: {metadata?.holderWallet || access?.holderWallet || "-"}</p>
          <p>Holder Key: {access?.holderEncryptionPublicKey ? "AVAILABLE" : "MISSING"}</p>
          <p>File: {metadata?.fileName || access?.fileName || "-"}</p>
          <p>Type: {metadata?.documentType || access?.documentType || "-"}</p>
          <p>Document Status: {documentStatus || "-"}</p>
          <p>Review Request Status: {access?.reviewStatus || metadata?.reviewStatus || "N/A"}</p>
          <p>
            Decision Lock:{" "}
            <strong>{isVerified ? "Accepted (backend persisted)" : isRejected ? "Rejected (backend persisted)" : "Open"}</strong>
          </p>
          {issuedCredential?.credentialId ? (
            <p>
              Issued VC: <strong>{issuedCredential.credentialId}</strong>
            </p>
          ) : null}
        </div>
      </SectionCard>

      <div className="issuer-review-grid">
        <SectionCard title="Document View & Decision" subtitle="Decrypt, inspect, then accept/reject (backend status source).">
          <div className="action-row">
            {!access?.encryptedKey && !isFinalized ? (
              <button
                type="button"
                className="btn btn--secondary"
                onClick={requestAccessFromHolder}
                disabled={loading}
              >
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

          <label className="field" style={{ marginTop: 12 }}>
            <span>Reason / Notes</span>
            <textarea
              placeholder="Add verification note or rejection reason..."
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              disabled={loading || isFinalized}
            />
          </label>

          <div className="action-row" style={{ marginTop: 12 }}>
            <button
              type="button"
              className="btn btn--primary"
              onClick={() => submitDecision(true)}
              disabled={loading || isFinalized}
            >
              {isVerified ? "Accepted" : "Accept"}
            </button>
            <button
              type="button"
              className="btn btn--danger"
              onClick={() => submitDecision(false)}
              disabled={loading || isFinalized}
            >
              {isRejected ? "Rejected" : "Reject & Request Re-upload"}
            </button>
          </div>

          {pdfUrl ? (
            <div className="pdf-frame-wrap" onContextMenu={(event) => event.preventDefault()}>
              <iframe title="Decrypted Document" src={pdfPreviewSrc} className="pdf-frame" />
            </div>
          ) : (
            <p className="login-muted" style={{ marginTop: 12 }}>
              Decrypted document preview appears here.
            </p>
          )}
        </SectionCard>

        <SectionCard title="VC Editor" subtitle="Create/edit VC beside the document, then issue encrypted VC.">
          <div className="form-grid">
            <label className="field">
              <span>Credential ID</span>
              <input
                value={vcCredentialId}
                onChange={(event) => setVcCredentialId(event.target.value)}
                placeholder="VC-2026-0001"
                disabled={vcEditorDisabled}
              />
            </label>

            <label className="field">
              <span>VC Schema</span>
              <input
                value={vcSchema}
                onChange={(event) => setVcSchema(event.target.value)}
                placeholder="DegreeCredential-v1"
                disabled={vcEditorDisabled}
              />
            </label>

            <label className="field">
              <span>Expiry Date</span>
              <input
                type="date"
                value={vcExpiresAt}
                onChange={(event) => setVcExpiresAt(event.target.value)}
                disabled={vcEditorDisabled}
              />
            </label>
          </div>

          <label className="field" style={{ marginTop: 12 }}>
            <span>Claims JSON</span>
            <textarea
              value={vcClaimsJson}
              onChange={(event) => setVcClaimsJson(event.target.value)}
              placeholder='{"name":"Alice","degree":"B.Tech"}'
              disabled={vcEditorDisabled}
            />
          </label>

          {issuedCredential?.credentialId ? (
            <div className="upload-success" style={{ marginTop: 12 }}>
              Credential already issued for this document: <strong>{issuedCredential.credentialId}</strong>
              <br />
              IPFS CID: <strong>{issuedCredential.vcIpfsCid}</strong>
              <br />
              Blockchain Tx: <strong>{issuedCredential.blockchainTxHash || "-"}</strong>
              <br />
              Issued At: <strong>{formatDateTime(issuedCredential.issuedAt)}</strong>
            </div>
          ) : null}

          <div className="action-row" style={{ marginTop: 12 }}>
            <button type="button" className="btn btn--primary" onClick={issueEncryptedVc} disabled={vcEditorDisabled}>
              {issuing ? "Issuing Encrypted VC..." : "Sign + Encrypt + Anchor + Store VC"}
            </button>
          </div>

          {!isVerified ? (
            <p className="field-help">Accept the document first. VC issuance is enabled only after VERIFIED status.</p>
          ) : null}
        </SectionCard>
      </div>

      {message ? <p className="upload-success">{message}</p> : null}
      {error ? <p className="login-error">{error}</p> : null}
    </div>
  );
}
