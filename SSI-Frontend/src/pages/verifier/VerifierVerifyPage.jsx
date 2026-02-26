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

const fmt = (value) => (value ? new Date(value).toLocaleString() : "-");

export default function VerifierVerifyPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const resolveVerifier = useCallback(async () => {
    let verifierId = userId || "";
    if (!verifierId) {
      verifierId = await refreshAuthSession();
    }
    return verifierId;
  }, [refreshAuthSession, userId]);

  const fetchRequests = useCallback(async () => {
    const verifierId = await resolveVerifier();
    if (!verifierId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/verifier/${verifierId}/requests`);
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not load proof requests."));
    }
    const data = await response.json();
    setRows(
      (Array.isArray(data) ? data : []).map((item) => ({
        id: item.requestId,
        requestId: item.requestId,
        credentialId: item.credentialId,
        holderWallet: item.holderWallet || "-",
        status: item.status || "-",
        verified: item.verificationStatus ? "VALID" : item.verificationStatus === false ? "INVALID" : "PENDING",
        respondedAt: fmt(item.respondedAt),
        verifiedAt: fmt(item.verifiedAt)
      }))
    );
  }, [resolveVerifier]);

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

  const reverify = async (requestId) => {
    const verifierId = await resolveVerifier();
    if (!verifierId) {
      setError("Verifier session not available.");
      return;
    }

    setLoading(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch(`${API_BASE_URL}/api/verifier/credentials/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ verifierId, requestId })
      });
      if (!response.ok) {
        throw new Error(await parseApiError(response, "Could not verify proof."));
      }
      setMessage("Proof re-verified successfully.");
      await fetchRequests();
    } catch (err) {
      setError(err.message || "Could not verify proof.");
    } finally {
      setLoading(false);
    }
  };

  const columns = useMemo(
    () => [
      { key: "requestId", header: "Request ID" },
      { key: "credentialId", header: "Credential ID" },
      { key: "holderWallet", header: "Holder" },
      { key: "status", header: "Request Status", render: (value) => <Badge value={value} /> },
      { key: "verified", header: "Verification", render: (value) => <Badge value={value} /> },
      { key: "respondedAt", header: "Holder Responded" },
      { key: "verifiedAt", header: "Verified At" },
      {
        key: "action",
        header: "Action",
        render: (_, row) => (
          <button
            type="button"
            className="btn btn--secondary"
            onClick={() => reverify(row.requestId)}
            disabled={loading}
          >
            Re-verify
          </button>
        )
      }
    ],
    [loading]
  );

  return (
    <div className="page-stack">
      <PageHeader title="Verify Proof" subtitle="Trigger verifier-side BBS proof + blockchain checks for a request." />
      <SectionCard title="Verification Workspace">
        {loading ? <p className="login-muted">Loading...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {message ? <p className="upload-success">{message}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
