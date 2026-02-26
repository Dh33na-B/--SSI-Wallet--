import { useCallback, useEffect, useMemo, useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
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

const formatDate = (value) => {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleDateString();
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

export default function HolderCredentialsPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchCredentials = useCallback(async () => {
    let holderId = userId || "";
    if (!holderId) {
      holderId = await refreshAuthSession();
    }
    if (!holderId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/holder/${holderId}/credentials`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load credentials."));
    }
    const data = await response.json();
    const mapped = (Array.isArray(data) ? data : []).map((item) => ({
      id: item.credentialId || item.id,
      issuer: item?.issuer?.walletAddress || "-",
      type: item?.document?.documentType?.name || "VerifiableCredential",
      issuedDate: formatDate(item.issuedAt),
      expiry: formatDate(item.expiresAt),
      revocationStatus: item?.revoked ? "REVOKED" : "ACTIVE",
      blockchainTx: shortText(item?.blockchainTxHash || "-", 24)
    }));
    setRows(mapped);
  }, [refreshAuthSession, userId]);

  useEffect(() => {
    const run = async () => {
      setIsLoading(true);
      setError("");
      try {
        await fetchCredentials();
      } catch (err) {
        setError(err.message || "Failed to load credentials.");
      } finally {
        setIsLoading(false);
      }
    };
    run();
  }, [fetchCredentials]);

  const columns = useMemo(
    () => [
      { key: "id", header: "Credential ID" },
      { key: "issuer", header: "Issuer" },
      { key: "type", header: "Type" },
      { key: "issuedDate", header: "Issued Date" },
      { key: "expiry", header: "Expiry" },
      { key: "revocationStatus", header: "Revocation Status", render: (value) => <Badge value={value} /> },
      { key: "blockchainTx", header: "Blockchain Tx" }
    ],
    []
  );

  return (
    <div className="page-stack">
      <PageHeader
        title="Received Credentials"
        subtitle="Live credentials issued by issuer after verification and signing."
      />

      <SectionCard title="Credential Wallet">
        {isLoading ? <p className="login-muted">Loading credentials...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>

      <SectionCard title="Security Restrictions">
        <ul className="helper-list">
          <li>Only encrypted VC payload CID is stored; plaintext VC is not shown here.</li>
          <li>Revocation status is read from backend state.</li>
        </ul>
      </SectionCard>
    </div>
  );
}
