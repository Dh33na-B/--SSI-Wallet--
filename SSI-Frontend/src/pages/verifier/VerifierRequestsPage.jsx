import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { verifierRequests } from "../../data/mockData";

export default function VerifierRequestsPage() {
  const columns = [
    { key: "id", header: "Request ID" },
    { key: "holderWallet", header: "Holder" },
    { key: "requestedFields", header: "Requested Fields" },
    { key: "sentAt", header: "Sent At" },
    { key: "expiry", header: "Expiry" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> }
  ];

  return (
    <div className="page-stack">
      <PageHeader title="Request Queue" subtitle="Track all sent proof requests and their response status." />
      <SectionCard title="Proof Request Records">
        <DataTable columns={columns} rows={verifierRequests} />
      </SectionCard>
    </div>
  );
}
