import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { issuedCredentials } from "../../data/mockData";

export default function IssuerAnchoringPage() {
  const rows = issuedCredentials.map((item) => ({
    credentialId: item.credentialId,
    holder: item.holder,
    hash: `hash:${item.credentialId.toLowerCase()}`,
    anchoredStatus: item.anchoredStatus,
    txHash: item.txHash
  }));

  const columns = [
    { key: "credentialId", header: "Credential ID" },
    { key: "holder", header: "Holder" },
    { key: "hash", header: "VC Hash" },
    { key: "anchoredStatus", header: "Status", render: (value) => <Badge value={value} /> },
    { key: "txHash", header: "Tx Hash" },
    {
      key: "actions",
      header: "Actions",
      render: (_, row) => (
        <div className="action-row">
          <button type="button" className="btn btn--secondary">
            Retry Anchor
          </button>
          <button type="button" className="btn btn--ghost">
            View {row.txHash === "-" ? "Queue" : "Explorer"}
          </button>
        </div>
      )
    }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Blockchain Anchoring" subtitle="Queue and transaction monitoring for credential hash anchoring." />
      <SectionCard title="Anchoring Queue">
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  );
}
