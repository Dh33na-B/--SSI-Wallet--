import { Link } from "react-router-dom";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function IssuerCredentialNewPage() {
  return (
    <div className="page-stack">
      <PageHeader
        title="Create Verifiable Credential"
        subtitle="VC editing is now embedded directly inside the document review workspace."
      />

      <SectionCard title="Updated Flow">
        <div className="helper-list">
          <p>1. Open a submission from the issuer queue.</p>
          <p>2. Decrypt and verify the document.</p>
          <p>3. Accept the document (status persists as VERIFIED).</p>
          <p>4. Edit and issue encrypted VC in the same review page beside the document preview.</p>
        </div>
        <div className="action-row" style={{ marginTop: 12 }}>
          <Link className="btn btn--primary" to="/issuer/submissions">
            Open Review Queue
          </Link>
        </div>
      </SectionCard>
    </div>
  );
}
