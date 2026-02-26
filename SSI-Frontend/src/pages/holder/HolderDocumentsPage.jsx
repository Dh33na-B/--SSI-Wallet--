import { base64, utf8 } from "@scure/base";
import { useCallback, useEffect, useMemo, useState } from "react";
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
  const [uploadOpen, setUploadOpen] = useState(false);
  const [documents, setDocuments] = useState([]);
  const [documentTypes, setDocumentTypes] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [uploadError, setUploadError] = useState("");
  const [uploadSuccess, setUploadSuccess] = useState("");

  const [selectedTypeId, setSelectedTypeId] = useState("");
  const [newTypeName, setNewTypeName] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);

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

    let effectiveHolderId = userId;
    if (!effectiveHolderId) {
      effectiveHolderId = await refreshAuthSession();
    }

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
  }, [userId, refreshAuthSession]);

  const fetchDocumentTypes = useCallback(async () => {
    const response = await fetch(`${API_BASE_URL}/api/holder/document-types`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load document types."));
    }
    const data = await response.json();
    setDocumentTypes(Array.isArray(data) ? data : []);
  }, []);

  const loadInitialData = useCallback(async () => {
    if (!userId) {
      return;
    }
    setIsLoading(true);
    setLoadError("");
    try {
      await Promise.all([fetchDocuments(), fetchDocumentTypes()]);
    } catch (error) {
      setLoadError(error.message || "Failed to load document data.");
    } finally {
      setIsLoading(false);
    }
  }, [fetchDocuments, fetchDocumentTypes, userId]);

  useEffect(() => {
    loadInitialData();
  }, [loadInitialData]);

  useEffect(() => {
    if (!uploadOpen) {
      setSelectedTypeId("");
      setNewTypeName("");
      setSelectedFile(null);
      setUploadError("");
    }
  }, [uploadOpen]);

  const columns = useMemo(
    () => [
      { key: "id", header: "Document ID", render: (value) => shortText(value, 20) },
      { key: "fileName", header: "File Name" },
      { key: "documentType", header: "Type", render: (value) => value || "-" },
      { key: "uploadedAt", header: "Uploaded On", render: (value) => formatDateTime(value) },
      { key: "ipfsCid", header: "IPFS CID", render: (value) => shortText(value, 24) },
      { key: "status", header: "Status", render: (value) => <Badge value={value} /> }
    ],
    []
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

  const encryptDocumentKeyWithWallet = async (wallet, keyBase64) => {
    if (!window.ethereum?.request) {
      throw new Error("MetaMask extension is required for key encryption.");
    }

    const encryptionPublicKey = await window.ethereum.request({
      method: "eth_getEncryptionPublicKey",
      params: [wallet]
    });

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

    return JSON.stringify(encryptedPayload);
  };

  const onFileChange = (event) => {
    const file = event.target.files?.[0] || null;
    setSelectedFile(file);
  };

  const onUpload = async () => {
    let holderId = userId || "";
    if (!holderId) {
      holderId = await refreshAuthSession();
    }
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

    setIsUploading(true);
    setUploadError("");
    setUploadSuccess("");

    try {
      const { encryptedBlob, keyBase64, ivBase64 } = await encryptDocument(selectedFile);
      const encryptedKey = await encryptDocumentKeyWithWallet(walletAddress, keyBase64);
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
          encryptedKey
        })
      });

      if (!response.ok) {
        throw new Error(await normalizeApiError(response, "Could not save uploaded document."));
      }

      await Promise.all([fetchDocuments(), fetchDocumentTypes()]);
      setUploadSuccess("Encrypted document uploaded to IPFS and saved successfully.");
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
    (selectedTypeId === NEW_TYPE_OPTION && !newTypeName.trim());

  return (
    <div className="page-stack">
      <PageHeader
        title="Documents"
        subtitle="Encrypted document uploads and issuer verification statuses."
        actions={
          <button type="button" className="btn btn--primary" onClick={() => setUploadOpen(true)}>
            Upload PDF
          </button>
        }
      />

      <SectionCard title="Upload New Document" subtitle="Encrypted before IPFS storage">
        <div className="upload-box">
          PDF is encrypted client-side using AES-256-GCM. The symmetric key is encrypted with your
          MetaMask public key before metadata is stored.
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
        title="Upload Encrypted Document"
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
