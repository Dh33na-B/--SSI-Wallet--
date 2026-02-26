import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import StatCard from "../../components/ui/StatCard";
import { holderCredentials, holderDocuments, holderProofRequests } from "../../data/mockData";

export default function HolderDashboardPage() {
  const columns = [
    { key: "id", header: "Request ID" },
    { key: "verifier", header: "Verifier" },
    { key: "requestedFields", header: "Requested Fields" },
    { key: "expiry", header: "Expiry" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> }
  ];

  return (
    <div className="page-stack">
      <PageHeader
        title="Holder Dashboard"
        subtitle="Manage documents, review proof requests, and control disclosure at field level."
      />

      <div className="stats-grid">
        <StatCard label="Wallet" value="Connected" trend="MetaMask active session" />
        <StatCard label="Documents" value={holderDocuments.length} trend="1 pending review" />
        <StatCard label="Credentials" value={holderCredentials.length} trend="All credentials active" />
        <StatCard label="Proof Requests" value={holderProofRequests.length} trend="1 action required" />
      </div>

      <div className="split-grid">
        <SectionCard title="Interaction Flow" subtitle="Suggested holder workflow">
          <ol className="helper-list">
            <li>Connect wallet and ensure session signature is valid.</li>
            <li>Upload encrypted document and wait for issuer status update.</li>
            <li>Receive credential and review incoming verifier requests.</li>
            <li>Select allowed fields, generate proof, then share.</li>
            <li>Track revocation status continuously.</li>
          </ol>
        </SectionCard>

        <SectionCard title="Security Notes" subtitle="Must remain hidden">
          <ul className="helper-list">
            <li>Never expose raw private key or seed phrase in UI state or logs.</li>
            <li>Never render encrypted document key material.</li>
            <li>Show only disclosed fields in proof preview, not full credential payload.</li>
          </ul>
        </SectionCard>
      </div>

      <SectionCard title="Pending / Recent Proof Requests">
        <DataTable columns={columns} rows={holderProofRequests} />
      </SectionCard>
    </div>
  );
}
