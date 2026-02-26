import { useState } from "react";
import Badge from "../../components/ui/Badge";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";

export default function VerifierVerifyPage() {
  const [signatureStatus, setSignatureStatus] = useState("PENDING");
  const [revocationStatus, setRevocationStatus] = useState("PENDING");

  return (
    <div className="page-stack">
      <PageHeader title="Verify Proof" subtitle="Upload received proof, verify BBS+ signature, and check revocation." />

      <SectionCard title="Upload Proof Package">
        <div className="upload-box">Drop proof JSON here or select file.</div>
        <div className="action-row" style={{ marginTop: 12 }}>
          <button type="button" className="btn btn--secondary" onClick={() => setSignatureStatus("VALID")}>
            Verify BBS+ Signature
          </button>
          <button type="button" className="btn btn--secondary" onClick={() => setRevocationStatus("NOT_REVOKED")}>
            Check Blockchain Revocation
          </button>
        </div>
      </SectionCard>

      <SectionCard title="Verification Result">
        <div className="helper-list">
          <p>
            Signature: <Badge value={signatureStatus} />
          </p>
          <p>
            Revocation: <Badge value={revocationStatus} />
          </p>
          <div className="action-row">
            <button type="button" className="btn btn--primary">
              Accept Credential
            </button>
            <button type="button" className="btn btn--danger">
              Reject Credential
            </button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}
