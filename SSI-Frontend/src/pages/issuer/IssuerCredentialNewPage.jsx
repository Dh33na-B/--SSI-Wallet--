import { useState } from "react";
import Modal from "../../components/ui/Modal";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function IssuerCredentialNewPage() {
  const [openSignModal, setOpenSignModal] = useState(false);

  return (
    <div className="page-stack">
      <PageHeader title="Create Verifiable Credential" subtitle="Compose VC claims, sign with BBS+, and publish." />

      <SectionCard title="VC Form">
        <div className="form-grid">
          <label className="field">
            <span>Holder DID / Wallet</span>
            <input placeholder="did:ethr:0x..." />
          </label>
          <label className="field">
            <span>Credential ID</span>
            <input placeholder="VC-2026-0001" />
          </label>
          <label className="field">
            <span>Schema</span>
            <select>
              <option>KYC v2</option>
              <option>Degree v1</option>
              <option>Employment v1</option>
            </select>
          </label>
          <label className="field">
            <span>Expiry</span>
            <input type="date" />
          </label>
        </div>
        <label className="field" style={{ marginTop: 12 }}>
          <span>Claims JSON</span>
          <textarea placeholder='{"fullName":"...","degree":"..."}' />
        </label>
      </SectionCard>

      <SectionCard title="Actions">
        <div className="action-row">
          <button type="button" className="btn btn--secondary">
            Save Draft
          </button>
          <button type="button" className="btn btn--primary" onClick={() => setOpenSignModal(true)}>
            Sign VC (BBS+)
          </button>
        </div>
      </SectionCard>

      <Modal
        open={openSignModal}
        title="BBS+ Signing Confirmation"
        onClose={() => setOpenSignModal(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setOpenSignModal(false)}>
              Cancel
            </button>
            <button type="button" className="btn btn--primary" onClick={() => setOpenSignModal(false)}>
              Confirm Sign
            </button>
          </>
        }
      >
        <p>This action will sign the VC with issuer BBS+ key material (never exposed in UI).</p>
      </Modal>
    </div>
  );
}
