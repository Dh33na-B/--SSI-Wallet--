import { useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { issuedCredentials } from "../../data/mockData";

export default function IssuerCredentialsPage() {
  const [anchorModalOpen, setAnchorModalOpen] = useState(false);

  const columns = [
    { key: "credentialId", header: "Credential ID" },
    { key: "holder", header: "Holder" },
    { key: "schema", header: "Schema" },
    { key: "signedStatus", header: "Signed", render: (value) => <Badge value={value} /> },
    { key: "anchoredStatus", header: "Anchored", render: (value) => <Badge value={value} /> },
    { key: "txHash", header: "Tx Hash" },
    { key: "revoked", header: "Revoked", render: (value) => <Badge value={value} /> },
    {
      key: "actions",
      header: "Actions",
      render: () => (
        <div className="action-row">
          <button type="button" className="btn btn--secondary">
            Sign VC
          </button>
          <button type="button" className="btn btn--primary" onClick={() => setAnchorModalOpen(true)}>
            Anchor Hash
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Issued Credentials" subtitle="Track VC signing, anchoring, and revocation state." />

      <SectionCard title="Credential Ledger">
        <DataTable columns={columns} rows={issuedCredentials} />
      </SectionCard>

      <Modal
        open={anchorModalOpen}
        title="Anchor Credential Hash"
        onClose={() => setAnchorModalOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setAnchorModalOpen(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn--primary" onClick={() => setAnchorModalOpen(false)}>
              Submit Transaction
            </button>
          </>
        }
      >
        <p>Anchoring pushes VC hash to Ethereum and stores tx hash in credential record.</p>
      </Modal>
    </div>
  );
}
