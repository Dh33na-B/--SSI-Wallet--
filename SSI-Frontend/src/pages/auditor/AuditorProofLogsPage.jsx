import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { auditProofLogs } from "../../data/mockData";

export default function AuditorProofLogsPage() {
  const columns = [
    { key: "logId", header: "Log ID" },
    { key: "verifier", header: "Verifier" },
    { key: "credentialId", header: "Credential ID" },
    { key: "signatureResult", header: "Signature", render: (value) => <Badge value={value} /> },
    { key: "revocationResult", header: "Revocation", render: (value) => <Badge value={value} /> },
    { key: "decision", header: "Decision", render: (value) => <Badge value={value} /> },
    { key: "timestamp", header: "Timestamp" }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Proof Verification Logs" subtitle="Traceability for every verifier decision." />
      <SectionCard title="Proof Log Table">
        <DataTable columns={columns} rows={auditProofLogs} />
      </SectionCard>
    </div>
  );
}
