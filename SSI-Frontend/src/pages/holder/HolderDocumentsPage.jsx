import { useState } from "react";
import Badge from "../../components/ui/Badge";
import DataTable from "../../components/ui/DataTable";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { holderDocuments } from "../../data/mockData";

export default function HolderDocumentsPage() {
  const [uploadOpen, setUploadOpen] = useState(false);

  const columns = [
    { key: "id", header: "Document ID" },
    { key: "fileName", header: "File Name" },
    { key: "uploadedOn", header: "Uploaded On" },
    { key: "ipfsCid", header: "IPFS CID" },
    { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
    { key: "issuer", header: "Issuer" },
    { key: "lastUpdated", header: "Last Updated" }
  ];

  return (
    <div className="page-stack">
      <PageHeader
        title="Documents"
        subtitle="Encrypted document uploads and issuer verification statuses."
        actions={
          <button type="button" className="btn btn--primary" onClick={() => setUploadOpen(true)}>
            Upload PDF
          </button>
        }
      />

      <SectionCard title="Upload New Document" subtitle="Encrypted before IPFS storage">
        <div className="upload-box">
          Drag and drop PDF here or use <strong>Upload PDF</strong> button.
        </div>
      </SectionCard>

      <SectionCard title="Document Registry">
        <DataTable columns={columns} rows={holderDocuments} />
      </SectionCard>

      <Modal
        open={uploadOpen}
        title="Upload Encrypted Document"
        onClose={() => setUploadOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setUploadOpen(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn--primary" onClick={() => setUploadOpen(false)}>
              Upload
            </button>
          </>
        }
      >
        <div className="form-grid">
          <label className="field">
            <span>Document Type</span>
            <select>
              <option>Passport</option>
              <option>Degree Certificate</option>
              <option>Address Proof</option>
            </select>
          </label>
          <label className="field">
            <span>Encrypted PDF</span>
            <input type="file" />
          </label>
        </div>
      </Modal>
    </div>
  );
}
