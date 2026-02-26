import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
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

const shortText = (value, max = 18) => {
  if (!value) {
    return "-";
  }
  if (value.length <= max) {
    return value;
  }
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
};

export default function IssuerSubmissionsPage() {
  const { userId, refreshAuthSession } = useAuth();
  const navigate = useNavigate();

  const [rows, setRows] = useState([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [actionMessage, setActionMessage] = useState("");

  const fetchQueue = useCallback(async () => {
    let issuerId = userId || "";
    if (!issuerId) {
      issuerId = await refreshAuthSession();
    }
    if (!issuerId) {
      setRows([]);
      return;
    }

    const response = await fetch(`${API_BASE_URL}/api/issuer/${issuerId}/documents`);
    if (!response.ok) {
      throw new Error(await normalizeApiError(response, "Could not load submitted documents."));
    }
    const data = await response.json();
    setRows(Array.isArray(data) ? data : []);
  }, [userId, refreshAuthSession]);

  useEffect(() => {
    const run = async () => {
      setIsLoading(true);
      setError("");
      try {
        await fetchQueue();
      } catch (err) {
        setError(err.message || "Failed to load submissions.");
      } finally {
        setIsLoading(false);
      }
    };
    run();
  }, [fetchQueue]);

  const onOpen = async (row) => {
    if (row.status === "REJECTED") {
      setActionMessage("This document was rejected. Holder must re-upload a new file.");
      return;
    }
    setActionMessage("");
    setError("");
    try {
      navigate(`/issuer/review/${row.id}`);
    } catch (err) {
      setError(err.message || "Could not open document review.");
    }
  };

  const columns = [
    { key: "id", header: "Document ID", render: (value) => shortText(value, 22) },
    { key: "holderWallet", header: "Holder Wallet", render: (value) => shortText(value, 22) },
    { key: "fileName", header: "File Name", render: (value) => value || "-" },
    { key: "documentType", header: "Document Type", render: (value) => value || "-" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    { key: "reviewStatus", header: "Review Request", render: (value) => <Badge value={value || "N/A"} /> },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) =>
        row.status === "REJECTED" ? (
          <span className="login-muted">Waiting re-upload</span>
        ) : (
          <button type="button" className="btn btn--ghost" onClick={() => onOpen(row)}>
            Open
          </button>
        )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Submitted Documents" subtitle="Open a document and decrypt using issuer key access." />

      <SectionCard title="Document Review Queue">
        {isLoading ? <p className="login-muted">Loading queue...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {actionMessage ? <p className="upload-success">{actionMessage}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
