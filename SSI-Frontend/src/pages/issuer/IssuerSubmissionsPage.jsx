import { useState } from "react";
import { Link } from "react-router-dom";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { issuerSubmissions } from "../../data/mockData";

export default function IssuerSubmissionsPage() {
  const [decision, setDecision] = useState({ open: false, row: null, action: "" });

  const columns = [
    { key: "id", header: "Document ID" },
    { key: "holderWallet", header: "Holder Wallet" },
    { key: "documentType", header: "Document Type" },
    { key: "submittedAt", header: "Submitted At" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    { key: "riskFlag", header: "Risk Flag", render: (value) => <Badge value={value} /> },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) => (
        <div className="action-row">
          <button type="button" className="btn btn--secondary" onClick={() => setDecision({ open: true, row, action: "APPROVE" })}>
            Approve
          </button>
          <button type="button" className="btn btn--danger" onClick={() => setDecision({ open: true, row, action: "REJECT" })}>
            Reject
          </button>
          <Link className="btn btn--ghost" to={`/issuer/review/${row.id}`}>
            Open
          </Link>
        </div>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Submitted Documents" subtitle="Issuer queue for approval or rejection decisions." />

      <SectionCard title="Document Review Queue">
        <DataTable columns={columns} rows={issuerSubmissions} />
      </SectionCard>

      <Modal
        open={decision.open}
        title={`${decision.action} Document`}
        onClose={() => setDecision({ open: false, row: null, action: "" })}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setDecision({ open: false, row: null, action: "" })}>
              Cancel
            </button>
            <button type="button" className={decision.action === "APPROVE" ? "btn btn--primary" : "btn btn--danger"} onClick={() => setDecision({ open: false, row: null, action: "" })}>
              Confirm
            </button>
          </>
        }
      >
        <label className="field">
          <span>Reason / Notes</span>
          <textarea placeholder="Write decision reason for audit logs..." />
        </label>
      </Modal>
    </div>
  );
}
