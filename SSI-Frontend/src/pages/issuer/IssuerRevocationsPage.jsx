import { useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { issuedCredentials } from "../../data/mockData";

export default function IssuerRevocationsPage() {
  const [open, setOpen] = useState(false);

  const rows = issuedCredentials.map((item) => ({
    credentialId: item.credentialId,
    holder: item.holder,
    issuedAt: item.issuedAt,
    revoked: item.revoked,
    txHash: item.txHash
  }));

  const columns = [
    { key: "credentialId", header: "Credential ID" },
    { key: "holder", header: "Holder" },
    { key: "issuedAt", header: "Issued At" },
    { key: "revoked", header: "Revoked", render: (value) => <Badge value={value} /> },
    { key: "txHash", header: "Chain Tx" },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) => (
        <button type="button" className="btn btn--danger" onClick={() => setOpen(true)}>
          Revoke {row.credentialId}
        </button>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Revoke Credentials" subtitle="Issuer-only action with auditable reason and chain update." />

      <SectionCard title="Revocation Console">
        <DataTable columns={columns} rows={rows} />
      </SectionCard>

      <Modal
        open={open}
        title="Revoke Credential"
        onClose={() => setOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn--danger" onClick={() => setOpen(false)}>
              Confirm Revoke
            </button>
          </>
        }
      >
        <label className="field">
          <span>Revocation reason</span>
          <textarea placeholder="Compliance violation / credential invalidation reason..." />
        </label>
      </Modal>
    </div>
  );
}
