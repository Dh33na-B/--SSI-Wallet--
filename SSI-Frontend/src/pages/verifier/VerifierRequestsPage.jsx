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

const fmtDateTime = (value) => (value ? new Date(value).toLocaleString() : "-");

export default function VerifierRequestsPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const fetchRows = useCallback(async () => {
    let verifierId = userId || "";
    if (!verifierId) {
      verifierId = await refreshAuthSession();
    }
    if (!verifierId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/verifier/${verifierId}/requests`);
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not load request queue."));
    }

    const data = await response.json();
    setRows(
      (Array.isArray(data) ? data : []).map((item) => ({
        id: item.requestId,
        requestId: item.requestId,
        credentialId: item.credentialId,
        holderWallet: item.holderWallet || "-",
        requestedFields: Array.isArray(item.requestedFields) ? item.requestedFields.join(", ") : "-",
        disclosedFields: Array.isArray(item.disclosedFields) ? item.disclosedFields.join(", ") : "-",
        status: item.status || "-",
        verificationStatus: item.verificationStatus ? "VALID" : item.verificationStatus === false ? "INVALID" : "PENDING",
        createdAt: fmtDateTime(item.createdAt),
        expiresAt: fmtDateTime(item.expiresAt),
        verifiedAt: fmtDateTime(item.verifiedAt)
      }))
    );
  }, [refreshAuthSession, userId]);

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError("");
      try {
        await fetchRows();
      } catch (err) {
        setError(err.message || "Could not load verifier requests.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [fetchRows]);

  const columns = useMemo(
    () => [
      { key: "requestId", header: "Request ID" },
      { key: "credentialId", header: "Credential ID" },
      { key: "holderWallet", header: "Holder" },
      { key: "requestedFields", header: "Requested Fields" },
      { key: "disclosedFields", header: "Disclosed Fields" },
      { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
      { key: "verificationStatus", header: "Verification", render: (value) => <Badge value={value} /> },
      { key: "createdAt", header: "Created" },
      { key: "expiresAt", header: "Expiry" },
      { key: "verifiedAt", header: "Verified At" }
    ],
    []
  );

  return (
    <div className="page-stack">
      <PageHeader title="Request Queue" subtitle="Live proof requests and holder disclosure outcomes." />
      <SectionCard title="Proof Request Records">
        {loading ? <p className="login-muted">Loading requests...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
