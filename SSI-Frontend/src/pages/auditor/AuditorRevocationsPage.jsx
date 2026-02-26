import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { auditRevocations } from "../../data/mockData";

export default function AuditorRevocationsPage() {
  const columns = [
    { key: "revocationId", header: "Revocation ID" },
    { key: "credentialId", header: "Credential ID" },
    { key: "issuer", header: "Issuer" },
    { key: "reason", header: "Reason" },
    { key: "revokedAt", header: "Revoked At" },
    { key: "chainTx", header: "Chain Tx" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Revocation History" subtitle="All revocation events with reason and blockchain status." />
      <SectionCard title="Revocation Ledger">
        <DataTable columns={columns} rows={auditRevocations} />
      </SectionCard>
    </div>
  );
}
