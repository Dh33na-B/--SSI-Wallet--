import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { auditActivityLogs } from "../../data/mockData";

export default function AuditorActivityLogsPage() {
  const columns = [
    { key: "eventId", header: "Event ID" },
    { key: "actorRole", header: "Actor Role" },
    { key: "actorId", header: "Actor ID" },
    { key: "action", header: "Action" },
    { key: "entityType", header: "Entity Type" },
    { key: "entityId", header: "Entity ID" },
    { key: "timestamp", header: "Timestamp" },
    { key: "device", header: "Device" }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="System Activity Logs" subtitle="Comprehensive event stream for compliance tracing." />
      <SectionCard title="Log Explorer">
        <div className="form-grid" style={{ marginBottom: 12 }}>
          <label className="field">
            <span>Date Range</span>
            <input type="date" />
          </label>
          <label className="field">
            <span>Role Filter</span>
            <select>
              <option>All Roles</option>
              <option>Holder</option>
              <option>Issuer</option>
              <option>Verifier</option>
            </select>
          </label>
          <label className="field">
            <span>Action Filter</span>
            <input placeholder="VERIFY_DOCUMENT" />
          </label>
        </div>
        <DataTable columns={columns} rows={auditActivityLogs} />
      </SectionCard>
    </div>
  );
}
