import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { verifierHistory } from "../../data/mockData";

export default function VerifierHistoryPage() {
  const columns = [
    { key: "verificationId", header: "Verification ID" },
    { key: "credentialId", header: "Credential ID" },
    { key: "holder", header: "Holder" },
    { key: "signatureResult", header: "Signature", render: (value) => <Badge value={value} /> },
    { key: "revocationResult", header: "Revocation", render: (value) => <Badge value={value} /> },
    { key: "finalDecision", header: "Decision", render: (value) => <Badge value={value} /> },
    { key: "verifiedAt", header: "Verified At" }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Verification History" subtitle="Audit trail of all verification decisions." />
      <SectionCard title="History Table">
        <DataTable columns={columns} rows={verifierHistory} />
      </SectionCard>
    </div>
  );
}
