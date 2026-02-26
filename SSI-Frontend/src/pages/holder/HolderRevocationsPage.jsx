import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { holderCredentials } from "../../data/mockData";

export default function HolderRevocationsPage() {
  const columns = [
    { key: "id", header: "Credential ID" },
    { key: "issuer", header: "Issuer" },
    { key: "issuedDate", header: "Issued Date" },
    { key: "expiry", header: "Expiry" },
    { key: "revocationStatus", header: "Revocation", render: (value) => <Badge value={value} /> },
    { key: "blockchainTx", header: "Chain Tx" }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Revocation Status" subtitle="Monitor credential validity from blockchain state." />
      <SectionCard title="Credential Revocation Monitor">
        <DataTable columns={columns} rows={holderCredentials} />
      </SectionCard>
    </div>
  );
}
