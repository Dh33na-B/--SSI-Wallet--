import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function AuditorAnalyticsPage() {
  const metrics = [
    { label: "Verification Failures", value: 31 },
    { label: "Revocations", value: 18 },
    { label: "Suspicious Alerts", value: 44 },
    { label: "Escalated Cases", value: 12 }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Analytics Dashboard" subtitle="Operational and compliance trend monitoring." />

      <SectionCard title="Event Distribution (Last 30 days)">
        <div className="chart-row">
          {metrics.map((metric) => (
            <div key={metric.label} className="chart-bar">
              <strong>{metric.label}</strong>
              <div className="chart-fill" style={{ width: `${Math.max(12, metric.value)}%` }} />
              <span>{metric.value}</span>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  );
}
