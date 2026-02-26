import { base64, utf8 } from "@scure/base";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import nacl from "tweetnacl";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";
const PINATA_UPLOAD_URL = "https://api.pinata.cloud/pinning/pinFileToIPFS";
const NEW_TYPE_OPTION = "__NEW_TYPE__";

const shortText = (value, max = 16) => {
  if (!value) {
    return "-";
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
};

const bytesToBase64 = (bytes) => {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return window.btoa(binary);
};

const bytesToHex = (bytes) =>
  `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;

const utf8ToHex = (value) => bytesToHex(new TextEncoder().encode(value));

const arrayBufferToBase64 = (buffer) => bytesToBase64(new Uint8Array(buffer));

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

const formatDateTime = (value) => {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
};

export default function HolderDocumentsPage() {
  const { userId, walletAddress, refreshAuthSession } = useAuth();
  const navigate = useNavigate();
  const [uploadOpen, setUploadOpen] = useState(false);
  const [documents, setDocuments] = useState([]);
  const [documentTypes, setDocumentTypes] = useState([]);
  const [issuers, setIssuers] = useState([]);
  const [pendingReviewCount, setPendingReviewCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [uploadSuccess, setUploadSuccess] = useState("");

  const [selectedTypeId, setSelectedTypeId] = useState("");
  const [newTypeName, setNewTypeName] = useState("");
  const [selectedIssuerId, setSelectedIssuerId] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [reuploadSource, setReuploadSource] = useState(null);

  const resolveHolderId = useCallback(async () => {
    let effectiveHolderId = userId;
    if (!effectiveHolderId) {
      effectiveHolderId = await refreshAuthSession();
    }
    return effectiveHolderId || "";
  }, [userId, refreshAuthSession]);

  const fetchDocuments = useCallback(async () => {
    const fetchByHolderId = async (holderId) => {
      const response = await fetch(`${API_BASE_URL}/api/holder/${holderId}/documents`);
      if (!response.ok) {
        const message = await normalizeApiError(response, "Could not load documents.");
        const error = new Error(message);
        error.status = response.status;
        throw error;
      }
      const data = await response.json();
      setDocuments(Array.isArray(data) ? data : []);
    };

    const effectiveHolderId = await resolveHolderId();

    if (!effectiveHolderId) {
      setDocuments([]);
      return;
    }

    try {
      await fetchByHolderId(effectiveHolderId);
    } catch (error) {
      const holderMissing =
        error?.status === 404 && String(error.message || "").toLowerCase().includes("holder not found");

      if (!holderMissing) {
        throw error;
      }

      const refreshedHolderId = await refreshAuthSession();
      if (!refreshedHolderId) {
        throw new Error("Session is out of sync. Logout and login again.");
      }

      await fetchByHolderId(refreshedHolderId);
    }
  }, [resolveHolderId, refreshAuthSession]);

  const fetchReviewRequestCount = useCallback(async () => {
    const holderId = await resolveHolderId();
    if (!holderId) {
      setPendingReviewCount(0);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/holder/${holderId}/review-requests`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load verification requests."));
    }
    const data = await response.json();
    const rows = Array.isArray(data) ? data : [];
    const pending = rows.filter((item) => item?.status === "REQUESTED").length;
    setPendingReviewCount(pending);
  }, [resolveHolderId]);

  const fetchDocumentTypes = useCallback(async () => {
    const response = await fetch(`${API_BASE_URL}/api/holder/document-types`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document types."));
    }
    const data = await response.json();
    setDocumentTypes(Array.isArray(data) ? data : []);
  }, []);

  const fetchIssuers = useCallback(async () => {
    const response = await fetch(`${API_BASE_URL}/api/holder/issuers`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load issuers."));
    }
    const data = await response.json();
    setIssuers(Array.isArray(data) ? data : []);
  }, []);

  const loadInitialData = useCallback(async () => {
    setIsLoading(true);
    setLoadError("");
    try {
      await Promise.all([fetchDocuments(), fetchDocumentTypes(), fetchIssuers(), fetchReviewRequestCount()]);
    } catch (error) {
      setLoadError(error.message || "Failed to load document data.");
    } finally {
      setIsLoading(false);
    }
  }, [fetchDocuments, fetchDocumentTypes, fetchIssuers, fetchReviewRequestCount]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  useEffect(() => {
    if (!uploadOpen) {
      setSelectedTypeId("");
      setNewTypeName("");
      setSelectedIssuerId("");
      setSelectedFile(null);
      setUploadError("");
      setReuploadSource(null);
    }
  }, [uploadOpen]);

  const openUploadModal = () => {
    setUploadSuccess("");
    setLoadError("");
    setUploadError("");
    setReuploadSource(null);
    setSelectedTypeId("");
    setNewTypeName("");
    setSelectedIssuerId("");
    setSelectedFile(null);
    setUploadOpen(true);
  };

  const openReuploadModal = useCallback(
    (document) => {
      setUploadSuccess("");
      setLoadError("");
      setUploadError("");
      setSelectedFile(null);
      setReuploadSource(document);
      setSelectedIssuerId("");

      const documentTypeName = String(document?.documentType || "").trim();
      if (!documentTypeName) {
        setSelectedTypeId("");
        setNewTypeName("");
        setUploadOpen(true);
        return;
      }

      const matchedType = documentTypes.find(
        (type) => String(type?.name || "").toLowerCase() === documentTypeName.toLowerCase()
      );

      if (matchedType?.id) {
        setSelectedTypeId(matchedType.id);
        setNewTypeName("");
      } else {
        setSelectedTypeId(NEW_TYPE_OPTION);
        setNewTypeName(documentTypeName);
      }

      setUploadOpen(true);
    },
    [documentTypes]
  );

  const columns = useMemo(
    () => [
      { key: "id", header: "Document ID", render: (value) => shortText(value, 20) },
      { key: "fileName", header: "File Name" },
      { key: "documentType", header: "Type", render: (value) => value || "-" },
      { key: "uploadedAt", header: "Uploaded On", render: (value) => formatDateTime(value) },
      { key: "ipfsCid", header: "IPFS CID", render: (value) => shortText(value, 24) },
      { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
      {
        key: "actions",
        header: "Actions",
        render: (_, row) =>
          row.status === "REJECTED" ? (
            <button type="button" className="btn btn--secondary" onClick={() => openReuploadModal(row)}>
              Re-upload
            </button>
          ) : (
            <span className="login-muted">-</span>
          )
      }
    ],
    [openReuploadModal]
  );

  const uploadToPinata = async (encryptedBlob, originalFileName) => {
    const jwt = import.meta.env.VITE_PINATA_JWT;
    const apiKey = import.meta.env.VITE_PINATA_API_KEY;
    const apiSecret = import.meta.env.VITE_PINATA_API_SECRET;

    if (!jwt && (!apiKey || !apiSecret)) {
      throw new Error(
        "Pinata credentials are missing. Set VITE_PINATA_JWT or VITE_PINATA_API_KEY + VITE_PINATA_API_SECRET."
      );
    }

    const encryptedFileName = `${originalFileName}.enc`;
    const formData = new FormData();
    formData.append("file", encryptedBlob, encryptedFileName);
    formData.append("pinataMetadata", JSON.stringify({ name: encryptedFileName }));

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

  const encryptDocument = async (file) => {
    const rawPdf = await file.arrayBuffer();
    const aesKey = await window.crypto.subtle.generateKey(
      {
        name: "AES-GCM",
        length: 256
      },
      true,
      ["encrypt", "decrypt"]
    );
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedBytes = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv
      },
      aesKey,
      rawPdf
    );

    const exportedKey = await window.crypto.subtle.exportKey("raw", aesKey);

    return {
      encryptedBlob: new Blob([encryptedBytes], { type: "application/octet-stream" }),
      keyBase64: arrayBufferToBase64(exportedKey),
      ivBase64: bytesToBase64(iv)
    };
  };

  const encryptDocumentKeyWithPublicKey = (encryptionPublicKey, keyBase64) => {
    const publicKeyBytes = base64.decode(encryptionPublicKey);
    const ephemeralKeyPair = nacl.box.keyPair();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const messageBytes = utf8.decode(keyBase64);
    const ciphertext = nacl.box(messageBytes, nonce, publicKeyBytes, ephemeralKeyPair.secretKey);

    const encryptedPayload = {
      version: "x25519-xsalsa20-poly1305",
      nonce: base64.encode(nonce),
      ephemPublicKey: base64.encode(ephemeralKeyPair.publicKey),
      ciphertext: base64.encode(ciphertext)
    };

    return utf8ToHex(JSON.stringify(encryptedPayload));
  };

  const encryptDocumentKeyWithWallet = async (wallet, keyBase64) => {
    if (!window.ethereum?.request) {
      throw new Error("MetaMask extension is required for key encryption.");
    }

    const encryptionPublicKey = await window.ethereum.request({
      method: "eth_getEncryptionPublicKey",
      params: [wallet]
    });
    return encryptDocumentKeyWithPublicKey(encryptionPublicKey, keyBase64);
  };

  const onFileChange = (event) => {
    const file = event.target.files?.[0] || null;
    setSelectedFile(file);
  };

  const onUpload = async () => {
    const holderId = await resolveHolderId();
    if (!holderId) {
      setUploadError("Login required before upload.");
      return;
    }
    if (!walletAddress) {
      setUploadError("Connect wallet before uploading a document.");
      return;
    }
    if (!selectedFile) {
      setUploadError("Select a PDF file.");
      return;
    }
    const fileNameLower = selectedFile.name.toLowerCase();
    const isPdf =
      selectedFile.type === "application/pdf" ||
      (!selectedFile.type && fileNameLower.endsWith(".pdf")) ||
      fileNameLower.endsWith(".pdf");
    if (!isPdf) {
      setUploadError("Only PDF files are supported.");
      return;
    }
    if (!selectedTypeId) {
      setUploadError("Select a document type.");
      return;
    }
    if (selectedTypeId === NEW_TYPE_OPTION && !newTypeName.trim()) {
      setUploadError("Enter the new document type name.");
      return;
    }
    if (!selectedIssuerId) {
      setUploadError("Select the issuer allowed to verify this document.");
      return;
    }

    setIsUploading(true);
    setUploadError("");
    setUploadSuccess("");

    try {
      const selectedIssuer = issuers.find((issuer) => issuer.issuerId === selectedIssuerId);
      if (!selectedIssuer?.issuerId || !selectedIssuer?.encryptionPublicKey) {
        throw new Error("Selected issuer does not have a valid encryption public key.");
      }

      const { encryptedBlob, keyBase64, ivBase64 } = await encryptDocument(selectedFile);
      const encryptedKeyForHolder = await encryptDocumentKeyWithWallet(walletAddress, keyBase64);
      const encryptedKeyForIssuer = encryptDocumentKeyWithPublicKey(
        selectedIssuer.encryptionPublicKey,
        keyBase64
      );
      const ipfsCid = await uploadToPinata(encryptedBlob, selectedFile.name);

      const response = await fetch(`${API_BASE_URL}/api/holder/documents/upload`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          holderId,
          documentTypeId: selectedTypeId === NEW_TYPE_OPTION ? null : selectedTypeId,
          newDocumentTypeName: selectedTypeId === NEW_TYPE_OPTION ? newTypeName.trim() : null,
          fileName: selectedFile.name,
          ipfsCid,
          encryptionIv: ivBase64,
          encryptedKey: encryptedKeyForHolder,
          recipientKeys: [
            {
              recipientUserId: selectedIssuer.issuerId,
              encryptedKey: encryptedKeyForIssuer
            }
          ]
        })
      });

      if (!response.ok) {
        throw new Error(await normalizeApiError(response, "Could not save uploaded document."));
      }

      await Promise.all([fetchDocuments(), fetchDocumentTypes(), fetchReviewRequestCount()]);
      setUploadSuccess(
        reuploadSource
          ? `Replacement uploaded for rejected document: ${reuploadSource.fileName || reuploadSource.id}.`
          : "Encrypted document uploaded to IPFS and saved successfully."
      );
      setUploadOpen(false);
    } catch (error) {
      setUploadError(error.message || "Document upload failed.");
    } finally {
      setIsUploading(false);
    }
  };

  const disableUploadButton =
    isUploading ||
    !selectedFile ||
    !selectedTypeId ||
    !selectedIssuerId ||
    (selectedTypeId === NEW_TYPE_OPTION && !newTypeName.trim());

  return (
    <div className="page-stack">
      <PageHeader
        title="Documents"
        subtitle="Encrypted document uploads and issuer verification statuses."
        actions={
          <div className="action-row">
            <button
              type="button"
              className="btn btn--secondary"
              onClick={() => navigate("/holder/verification-requests")}
            >
              Verification Requests ({pendingReviewCount})
            </button>
            <button type="button" className="btn btn--primary" onClick={openUploadModal}>
              Upload PDF
            </button>
          </div>
        }
      />

      <SectionCard title="Upload New Document" subtitle="Encrypted before IPFS storage">
        <div className="upload-box">
          PDF is encrypted client-side using AES-256-GCM. The symmetric key is encrypted with your
          MetaMask public key and with the selected issuer public key before metadata is stored.
        </div>
      </SectionCard>

      <SectionCard title="Verification Access Requests" subtitle="Approve request to allow decryption for verification">
        <div className="upload-box">
          {pendingReviewCount > 0
            ? `You have ${pendingReviewCount} pending approval request(s).`
            : "No pending requests right now."}
        </div>
        <div className="action-row">
          <button
            type="button"
            className="btn btn--secondary"
            onClick={() => navigate("/holder/verification-requests")}
          >
            Open Verification Requests
          </button>
        </div>
      </SectionCard>

      <SectionCard title="Document Registry">
        {isLoading ? <p className="login-muted">Loading documents...</p> : null}
        {loadError ? <p className="login-error">{loadError}</p> : null}
        {uploadSuccess ? <p className="upload-success">{uploadSuccess}</p> : null}
        <DataTable columns={columns} rows={documents} />
      </SectionCard>

      <Modal
        open={uploadOpen}
        title={reuploadSource ? "Re-upload Rejected Document" : "Upload Encrypted Document"}
        onClose={() => setUploadOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setUploadOpen(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn--primary"
              onClick={onUpload}
              disabled={disableUploadButton}
            >
              {isUploading ? "Encrypting & Uploading..." : "Upload"}
            </button>
          </>
        }
      >
        <div className="form-grid">
          {reuploadSource ? (
            <div className="upload-box">
              Re-uploading <strong>{reuploadSource.fileName || "selected document"}</strong>. The old CID
              is already removed after rejection.
            </div>
          ) : null}

          <label className="field">
            <span>Document Type</span>
            <select
              value={selectedTypeId}
              onChange={(event) => setSelectedTypeId(event.target.value)}
              disabled={isUploading}
            >
              <option value="">Select type</option>
              {documentTypes.map((type) => (
                <option key={type.id} value={type.id}>
                  {type.name}
                </option>
              ))}
              <option value={NEW_TYPE_OPTION}>+ Add new type</option>
            </select>
          </label>

          <label className="field">
            <span>Authorized Issuer</span>
            <select
              value={selectedIssuerId}
              onChange={(event) => setSelectedIssuerId(event.target.value)}
              disabled={isUploading}
            >
              <option value="">Select issuer</option>
              {issuers.map((issuer) => (
                <option key={issuer.issuerId} value={issuer.issuerId}>
                  {shortText(issuer.walletAddress, 26)}
                </option>
              ))}
            </select>
          </label>
          {!issuers.length ? (
            <p className="field-help">No issuer with encryption key is registered yet.</p>
          ) : null}

          {selectedTypeId === NEW_TYPE_OPTION ? (
            <label className="field">
              <span>New Type Name</span>
              <input
                type="text"
                placeholder="e.g. Employment Letter"
                value={newTypeName}
                onChange={(event) => setNewTypeName(event.target.value)}
                disabled={isUploading}
              />
            </label>
          ) : null}

          <label className="field">
            <span>PDF File</span>
            <input type="file" accept="application/pdf,.pdf" onChange={onFileChange} disabled={isUploading} />
          </label>
        </div>

        {selectedFile ? (
          <p className="field-help">
            Selected: <strong>{selectedFile.name}</strong>
          </p>
        ) : null}

        <p className="field-help">
          Pinata upload requires `VITE_PINATA_JWT` or `VITE_PINATA_API_KEY` +
          `VITE_PINATA_API_SECRET`.
        </p>

        {uploadError ? <p className="login-error">{uploadError}</p> : null}
      </Modal>
    </div>
  );
}
