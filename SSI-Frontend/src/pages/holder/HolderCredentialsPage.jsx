import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { holderCredentials } from "../../data/mockData";

export default function HolderCredentialsPage() {
  const columns = [
    { key: "id", header: "Credential ID" },
    { key: "issuer", header: "Issuer" },
    { key: "type", header: "Type" },
    { key: "issuedDate", header: "Issued Date" },
    { key: "expiry", header: "Expiry" },
    { key: "revocationStatus", header: "Revocation Status", render: (value) => <Badge value={value} /> },
    { key: "blockchainTx", header: "Blockchain Tx" }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Received Credentials" subtitle="Credential inventory available for selective disclosure." />

      <SectionCard title="Credential Wallet">
        <DataTable columns={columns} rows={holderCredentials} />
      </SectionCard>

      <SectionCard title="Security Restrictions">
        <ul className="helper-list">
          <li>Full credential JSON should never be displayed to verifier-facing screens.</li>
          <li>Do not expose hidden fields during proof generation preview.</li>
          <li>Keep raw BBS+ signature payload internal-only.</li>
        </ul>
      </SectionCard>
    </div>
  );
}
