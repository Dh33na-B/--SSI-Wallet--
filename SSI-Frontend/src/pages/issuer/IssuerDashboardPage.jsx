import { Link } from "react-router-dom";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import StatCard from "../../components/ui/StatCard";
import { issuedCredentials, issuerSubmissions } from "../../data/mockData";

export default function IssuerDashboardPage() {
  return (
    <div className="page-stack">
      <PageHeader title="Issuer Dashboard" subtitle="Review queue, credential issuance, and chain anchoring status." />

      <div className="stats-grid">
        <StatCard label="Pending Reviews" value={issuerSubmissions.length} trend="2 need decisions" />
        <StatCard label="Issued Credentials" value={issuedCredentials.length} trend="1 drafted today" />
        <StatCard label="Signed (BBS+)" value="1" trend="Ready for anchoring" />
        <StatCard label="Revoked" value="0" trend="No active incidents" />
      </div>

      <div className="split-grid">
        <SectionCard title="Workflow">
          <ol className="helper-list">
            <li>Review submitted document and approve/reject.</li>
            <li>Create VC claims and sign with BBS+.</li>
            <li>Anchor hash to blockchain and monitor tx.</li>
            <li>Revoke credential if compliance issue appears.</li>
          </ol>
        </SectionCard>

        <SectionCard
          title="Quick Actions"
          right={
            <Link className="btn btn--secondary" to="/issuer/submissions">
              Open Queue
            </Link>
          }
        >
          <div className="action-row">
            <Link className="btn btn--primary" to="/issuer/credentials/new">
              Create VC
            </Link>
            <Link className="btn btn--ghost" to="/issuer/anchoring">
              Anchoring Panel
            </Link>
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
