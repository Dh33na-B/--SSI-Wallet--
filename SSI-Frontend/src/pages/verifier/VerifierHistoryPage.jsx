import { useCallback, useEffect, useMemo, useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

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

const fmtDate = (value) => (value ? new Date(value).toLocaleString() : "-");
const short = (value) => (value && value.length > 18 ? `${value.slice(0, 8)}...${value.slice(-6)}` : value || "-");

export default function VerifierHistoryPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadHistory = useCallback(async () => {
    let verifierId = userId || "";
    if (!verifierId) {
      verifierId = await refreshAuthSession();
    }
    if (!verifierId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/verifier/${verifierId}/history`);
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not load verification history."));
    }

    const data = await response.json();
    setRows(
      (Array.isArray(data) ? data : []).map((item) => ({
        id: item.id,
        verificationId: short(item.id),
        requestId: short(item?.verificationRequest?.id || "-"),
        credentialId: item?.credential?.credentialId || "-",
        holder: item?.credential?.holder?.walletAddress || item?.credential?.document?.user?.walletAddress || "-",
        signatureResult: item.signatureValid ? "VALID" : item.signatureValid === false ? "INVALID" : "-",
        hashResult: item.vcHashMatches ? "MATCH" : item.vcHashMatches === false ? "MISMATCH" : "-",
        revocationResult:
          item.blockchainRevoked === true
            ? "REVOKED"
            : item.blockchainRevoked === false
              ? "NOT_REVOKED"
              : "-",
        anchored: item.blockchainAnchored ? "ANCHORED" : item.blockchainAnchored === false ? "MISSING" : "-",
        finalDecision: item.verificationStatus ? "VALID" : item.verificationStatus === false ? "INVALID" : "-",
        verifiedAt: fmtDate(item.verifiedAt)
      }))
    );
  }, [refreshAuthSession, userId]);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError("");
      try {
        await loadHistory();
      } catch (err) {
        setError(err.message || "Could not load history.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [loadHistory]);

  const columns = useMemo(
    () => [
      { key: "verificationId", header: "Verification ID" },
      { key: "requestId", header: "Request ID" },
      { key: "credentialId", header: "Credential ID" },
      { key: "holder", header: "Holder" },
      { key: "signatureResult", header: "BBS+ Proof", render: (value) => <Badge value={value} /> },
      { key: "hashResult", header: "VC Hash", render: (value) => <Badge value={value} /> },
      { key: "anchored", header: "Anchored", render: (value) => <Badge value={value} /> },
      { key: "revocationResult", header: "Revocation", render: (value) => <Badge value={value} /> },
      { key: "finalDecision", header: "Decision", render: (value) => <Badge value={value} /> },
      { key: "verifiedAt", header: "Verified At" }
    ],
    []
  );

  return (
    <div className="page-stack">
      <PageHeader title="Verification History" subtitle="Audit trail of BBS proof checks and blockchain status checks." />
      <SectionCard title="History Table">
        {loading ? <p className="login-muted">Loading history...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
