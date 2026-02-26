import { useMemo, useState } from "react";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { holderCredentials } from "../../data/mockData";

export default function HolderProofBuilderPage() {
  const [selectedCredential, setSelectedCredential] = useState(holderCredentials[0]?.id || "");
  const [selectedFields, setSelectedFields] = useState([]);
  const [proofReady, setProofReady] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);

  const credential = useMemo(
    () => holderCredentials.find((item) => item.id === selectedCredential),
    [selectedCredential]
  );

  const toggleField = (field) => {
    setSelectedFields((prev) =>
      prev.includes(field) ? prev.filter((value) => value !== field) : [...prev, field]
    );
  };

  const generateProof = () => {
    if (selectedFields.length > 0) {
      setProofReady(true);
    }
  };

  return (
    <div className="page-stack">
      <PageHeader
        title="Selective Disclosure Proof Builder"
        subtitle="Step 1: Select credential/document. Step 2: Select fields. Step 3: Generate and share proof."
      />

      <SectionCard title="Step 1: Select Credential">
        <label className="field">
          <span>Credential</span>
          <select
            value={selectedCredential}
            onChange={(e) => {
              setSelectedCredential(e.target.value);
              setSelectedFields([]);
              setProofReady(false);
            }}
          >
            {holderCredentials.map((item) => (
              <option key={item.id} value={item.id}>
                {item.id} ({item.type})
              </option>
            ))}
          </select>
        </label>
      </SectionCard>

      <SectionCard title="Step 2: Select Fields for Disclosure">
        <div className="field-grid">
          {(credential?.fields || []).map((field) => (
            <label key={field} className="field-chip">
              <input
                type="checkbox"
                checked={selectedFields.includes(field)}
                onChange={() => toggleField(field)}
              />
              <span>{field}</span>
            </label>
          ))}
        </div>
      </SectionCard>

      <SectionCard title="Step 3: Generate & Share">
        <div className="action-row">
          <button type="button" className="btn btn--primary" onClick={generateProof}>
            Generate Proof
          </button>
          <button
            type="button"
            className="btn btn--secondary"
            disabled={!proofReady}
            onClick={() => setShareOpen(true)}
          >
            Share Proof
          </button>
        </div>
        {proofReady ? (
          <p className="login-wallet">
            Proof generated for {selectedCredential}. Included fields: {selectedFields.join(", ")}
          </p>
        ) : null}
      </SectionCard>

      <Modal
        open={shareOpen}
        title="Share Proof"
        onClose={() => setShareOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setShareOpen(false)}>
              Close
            </button>
            <button type="button" className="btn btn--primary" onClick={() => setShareOpen(false)}>
              Copy Share Link
            </button>
          </>
        }
      >
        <p>Proof share URL:</p>
        <p className="login-wallet">https://ssi.app/proof/share/PRF-92X-AB31</p>
      </Modal>
    </div>
  );
}
