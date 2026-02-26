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

const shortText = (value, max = 24) => {
  if (!value) {
    return "-";
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
};

export default function IssuerCredentialsPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchCredentials = useCallback(async () => {
    let issuerId = userId || "";
    if (!issuerId) {
      issuerId = await refreshAuthSession();
    }
    if (!issuerId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/credentials`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load issued credentials."));
    }
    const data = await response.json();
    const mapped = (Array.isArray(data) ? data : []).map((item) => ({
      id: item.credentialId || item.id,
      credentialId: item.credentialId || "-",
      holder: shortText(item?.holder?.walletAddress || "-", 22),
      schema: item?.document?.documentType?.name || "VerifiableCredential",
      signedStatus: item?.signatureSuite ? "SIGNED" : "DRAFT",
      anchoredStatus: item?.blockchainTxHash ? "ANCHORED" : "PENDING",
      txHash: shortText(item?.blockchainTxHash || "-", 24),
      revoked: item?.revoked ? "YES" : "NO"
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
        setError(err.message || "Failed to load issued credentials.");
      } finally {
        setIsLoading(false);
      }
    };
    run();
  }, [fetchCredentials]);

  const columns = useMemo(
    () => [
      { key: "credentialId", header: "Credential ID" },
      { key: "holder", header: "Holder" },
      { key: "schema", header: "Schema" },
      { key: "signedStatus", header: "Signed", render: (value) => <Badge value={value} /> },
      { key: "anchoredStatus", header: "Anchored", render: (value) => <Badge value={value} /> },
      { key: "txHash", header: "Tx Hash" },
      { key: "revoked", header: "Revoked", render: (value) => <Badge value={value} /> }
    ],
    []
  );

  return (
    <div className="page-stack">
      <PageHeader
        title="Issued Credentials"
        subtitle="Read-only ledger from backend state. Signing and anchoring are done during VC issuance."
      />

      <SectionCard title="Credential Ledger">
        {isLoading ? <p className="login-muted">Loading credentials...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
