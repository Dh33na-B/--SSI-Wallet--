import { useParams } from "react-router-dom";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { issuerSubmissions } from "../../data/mockData";

export default function IssuerReviewPage() {
  const { documentId } = useParams();
  const record = issuerSubmissions.find((item) => item.id === documentId);

  return (
    <div className="page-stack">
      <PageHeader title={`Review ${documentId}`} subtitle="Detailed review before issuing credential." />

      <SectionCard title="Document Metadata">
        <div className="helper-list">
          <p>Holder: {record?.holderWallet || "-"}</p>
          <p>Type: {record?.documentType || "-"}</p>
          <p>Submitted: {record?.submittedAt || "-"}</p>
          <p>Risk: {record?.riskFlag || "-"}</p>
        </div>
      </SectionCard>

      <SectionCard title="Review Actions">
        <div className="action-row">
          <button type="button" className="btn btn--primary">
            Approve
          </button>
          <button type="button" className="btn btn--danger">
            Reject
          </button>
          <button type="button" className="btn btn--ghost">
            Request Re-upload
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
