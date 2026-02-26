import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import StatCard from "../../components/ui/StatCard";
import { auditActivityLogs, auditProofLogs, auditRevocations, suspiciousAlerts } from "../../data/mockData";

export default function AuditorDashboardPage() {
  return (
    <div className="page-stack">
      <PageHeader title="Auditor Dashboard" subtitle="Read-only compliance view across activity, revocations, and proofs." />

      <div className="stats-grid">
        <StatCard label="Activity Events" value={auditActivityLogs.length} trend="Latest 24h" />
        <StatCard label="Revocations" value={auditRevocations.length} trend="1 confirmed action" />
        <StatCard label="Proof Logs" value={auditProofLogs.length} trend="Verification trend stable" />
        <StatCard label="Suspicious Alerts" value={suspiciousAlerts.length} trend="1 high severity" />
      </div>

      <SectionCard title="Security Boundaries">
        <ul className="helper-list">
          <li>Auditor cannot revoke credentials, sign VC, or request proofs.</li>
          <li>Auditor cannot access private keys or decrypted document payloads.</li>
          <li>Audit screens must remain immutable except review annotations.</li>
        </ul>
      </SectionCard>
    </div>
  );
}
