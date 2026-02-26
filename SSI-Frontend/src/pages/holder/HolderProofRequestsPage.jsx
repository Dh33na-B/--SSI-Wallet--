import { useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { holderProofRequests } from "../../data/mockData";

export default function HolderProofRequestsPage() {
  const [decisionModal, setDecisionModal] = useState({ open: false, request: null, action: "" });

  const openDecision = (request, action) => {
    setDecisionModal({ open: true, request, action });
  };

  const columns = [
    { key: "id", header: "Request ID" },
    { key: "verifier", header: "Verifier" },
    { key: "requestedFields", header: "Requested Fields" },
    { key: "requestedAt", header: "Requested At" },
    { key: "expiry", header: "Expiry" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) => (
        <div className="action-row">
          <button type="button" className="btn btn--secondary" onClick={() => openDecision(row, "ACCEPT")}>
            Accept
          </button>
          <button type="button" className="btn btn--danger" onClick={() => openDecision(row, "REJECT")}>
            Reject
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader
        title="Proof Requests"
        subtitle="Review requests from verifiers and explicitly accept or reject each request."
      />

      <SectionCard title="Incoming Requests">
        <DataTable columns={columns} rows={holderProofRequests} />
      </SectionCard>

      <Modal
        open={decisionModal.open}
        title={`${decisionModal.action} Proof Request`}
        onClose={() => setDecisionModal({ open: false, request: null, action: "" })}
        footer={
          <>
            <button
              type="button"
              className="btn btn--ghost"
              onClick={() => setDecisionModal({ open: false, request: null, action: "" })}
            >
              Cancel
            </button>
            <button
              type="button"
              className={decisionModal.action === "ACCEPT" ? "btn btn--primary" : "btn btn--danger"}
              onClick={() => setDecisionModal({ open: false, request: null, action: "" })}
            >
              Confirm {decisionModal.action}
            </button>
          </>
        }
      >
        <p>
          Request: <strong>{decisionModal.request?.id}</strong>
        </p>
        <p>
          Verifier: <strong>{decisionModal.request?.verifier}</strong>
        </p>
        <p>Only approved fields will be exposed in proof generation.</p>
      </Modal>
    </div>
  );
}
