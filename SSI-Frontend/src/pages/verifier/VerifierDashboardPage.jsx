import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import StatCard from "../../components/ui/StatCard";
import { verifierHistory, verifierRequests } from "../../data/mockData";

export default function VerifierDashboardPage() {
  return (
    <div className="page-stack">
      <PageHeader title="Verifier Dashboard" subtitle="Request, verify, decide, and track proof outcomes." />

      <div className="stats-grid">
        <StatCard label="Active Requests" value={verifierRequests.length} trend="1 proof received" />
        <StatCard label="Verifications Today" value={verifierHistory.length} trend="1 accepted / 1 rejected" />
        <StatCard label="BBS+ Valid" value="2" trend="No signature failures" />
        <StatCard label="Revoked Found" value="1" trend="Escalated for review" />
      </div>

      <SectionCard title="Flow">
        <ol className="helper-list">
          <li>Create selective field request and send to holder.</li>
          <li>Receive or upload proof package.</li>
          <li>Verify BBS+ signature and check on-chain revocation.</li>
          <li>Accept or reject and record decision.</li>
        </ol>
      </SectionCard>
    </div>
  );
}
