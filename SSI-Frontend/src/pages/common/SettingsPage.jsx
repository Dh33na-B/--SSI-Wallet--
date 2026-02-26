import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function SettingsPage({ role }) {
  return (
    <div className="page-stack">
      <PageHeader title={`${role} Settings`} subtitle="Environment preferences, notifications, and session controls." />

      <SectionCard title="Preferences" subtitle="UI and interaction settings">
        <div className="form-grid">
          <label className="field">
            <span>Timezone</span>
            <select>
              <option>UTC</option>
              <option>Asia/Kolkata</option>
              <option>US/Eastern</option>
            </select>
          </label>
          <label className="field">
            <span>Notification Level</span>
            <select>
              <option>Critical only</option>
              <option>All important</option>
              <option>Everything</option>
            </select>
          </label>
        </div>
      </SectionCard>
    </div>
  );
}
