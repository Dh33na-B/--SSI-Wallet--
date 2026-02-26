import { useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { suspiciousAlerts } from "../../data/mockData";

export default function AuditorAlertsPage() {
  const [open, setOpen] = useState(false);

  const columns = [
    { key: "id", header: "Alert ID" },
    { key: "severity", header: "Severity", render: (value) => <Badge value={value} /> },
    { key: "summary", header: "Summary" },
    { key: "impactedEntity", header: "Impacted Entity" },
    { key: "createdAt", header: "Created At" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    {
      key: "actions",
      header: "Actions",
      render: () => (
        <div className="action-row">
          <button type="button" className="btn btn--secondary">
            Mark Investigated
          </button>
          <button type="button" className="btn btn--danger" onClick={() => setOpen(true)}>
            Escalate
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Suspicious Activity" subtitle="Risk alerts and escalation console." />
      <SectionCard title="Alert Queue">
        <DataTable columns={columns} rows={suspiciousAlerts} />
      </SectionCard>

      <Modal
        open={open}
        title="Escalate Alert"
        onClose={() => setOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn--danger" onClick={() => setOpen(false)}>
              Escalate
            </button>
          </>
        }
      >
        <label className="field">
          <span>Escalation Note</span>
          <textarea placeholder="Provide incident context and recommended action..." />
        </label>
      </Modal>
    </div>
  );
}
