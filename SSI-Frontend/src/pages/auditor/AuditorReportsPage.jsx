import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function AuditorReportsPage() {
  return (
    <div className="page-stack">
      <PageHeader title="Reports" subtitle="Generate compliance exports for review boards." />

      <SectionCard title="Export Options">
        <div className="action-row">
          <button type="button" className="btn btn--secondary">
            Export Activity Logs (CSV)
          </button>
          <button type="button" className="btn btn--secondary">
            Export Revocation Report (PDF)
          </button>
          <button type="button" className="btn btn--primary">
            Generate Monthly Compliance Pack
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
