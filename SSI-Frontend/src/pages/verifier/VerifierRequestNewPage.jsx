import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function VerifierRequestNewPage() {
  return (
    <div className="page-stack">
      <PageHeader title="Request Proof" subtitle="Ask holder only for minimum required fields." />

      <SectionCard title="New Proof Request">
        <div className="form-grid">
          <label className="field">
            <span>Holder Wallet / DID</span>
            <input placeholder="did:ethr:0x..." />
          </label>
          <label className="field">
            <span>Credential ID</span>
            <input placeholder="VC-ENG-2026-001" />
          </label>
          <label className="field">
            <span>Request Expiry</span>
            <input type="datetime-local" />
          </label>
          <label className="field">
            <span>Required Fields</span>
            <input placeholder="fullName, degree, graduationYear" />
          </label>
        </div>
        <div className="action-row" style={{ marginTop: 12 }}>
          <button type="button" className="btn btn--primary">
            Send Request
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
