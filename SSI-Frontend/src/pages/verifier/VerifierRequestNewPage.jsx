import { useCallback, useEffect, useMemo, useState } from "react";
import PageHeader from "../../components/ui/PageHeader";
import SectionCard from "../../components/ui/SectionCard";
import { useAuth } from "../../context/AuthContext";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080";

const parseApiError = async (response, fallback) => {
  try {
    const data = await response.json();
    if (data?.message) {
      return data.message;
    }
  } catch {
    // ignore
  }
  return fallback;
};

const splitFields = (value) =>
  value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

export default function VerifierRequestNewPage() {
  const { userId, refreshAuthSession } = useAuth();
  const [holders, setHolders] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [holderId, setHolderId] = useState("");
  const [credentialId, setCredentialId] = useState("");
  const [requiredFields, setRequiredFields] = useState("credentialSubject.degree, credentialSubject.institution");
  const [purpose, setPurpose] = useState("Employment verification");
  const [expiresAt, setExpiresAt] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const resolveVerifierId = useCallback(async () => {
    let verifierId = userId || "";
    if (!verifierId) {
      verifierId = await refreshAuthSession();
    }
    return verifierId;
  }, [refreshAuthSession, userId]);

  const loadHolders = useCallback(async () => {
    const verifierId = await resolveVerifierId();
    if (!verifierId) {
      setHolders([]);
      return;
    }
    const response = await fetch(`${API_BASE_URL}/api/verifier/${verifierId}/holders`);
    if (!response.ok) {
      throw new Error(await parseApiError(response, "Could not load holders."));
    }
    const data = await response.json();
    setHolders(Array.isArray(data) ? data : []);
  }, [resolveVerifierId]);

  const loadCredentials = useCallback(
    async (selectedHolderId) => {
      const verifierId = await resolveVerifierId();
      if (!verifierId || !selectedHolderId) {
        setCredentials([]);
        return;
      }
      const response = await fetch(
        `${API_BASE_URL}/api/verifier/${verifierId}/holders/${selectedHolderId}/credentials`
      );
      if (!response.ok) {
        throw new Error(await parseApiError(response, "Could not load holder credentials."));
      }
      const data = await response.json();
      setCredentials(Array.isArray(data) ? data : []);
    },
    [resolveVerifierId]
  );

  useEffect(() => {
    const run = async () => {
      setLoading(true);
      setError("");
      try {
        await loadHolders();
      } catch (err) {
        setError(err.message || "Could not load holders.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [loadHolders]);

  useEffect(() => {
    setCredentialId("");
    if (!holderId) {
      setCredentials([]);
      return;
    }
    const run = async () => {
      setLoading(true);
      setError("");
      try {
        await loadCredentials(holderId);
      } catch (err) {
        setError(err.message || "Could not load credentials.");
      } finally {
        setLoading(false);
      }
    };
    run();
  }, [holderId, loadCredentials]);

  const selectedHolder = useMemo(
    () => holders.find((item) => item.holderId === holderId),
    [holderId, holders]
  );

  const handleSubmit = async () => {
    setError("");
    setSuccess("");

    const fields = splitFields(requiredFields);
    if (!holderId || !credentialId || fields.length === 0) {
      setError("Select holder and credential, and provide at least one required field.");
      return;
    }

    const verifierId = await resolveVerifierId();
    if (!verifierId) {
      setError("Verifier session not available.");
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/verifier/proof/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          verifierId,
          holderId,
          credentialId,
          requestedFields: fields,
          purpose: purpose.trim() || null,
          expiresAt: expiresAt || null
        })
      });
      if (!response.ok) {
        throw new Error(await parseApiError(response, "Could not create proof request."));
      }
      const data = await response.json();
      setSuccess(`Proof request created: ${data?.requestId || "unknown request id"}`);
    } catch (err) {
      setError(err.message || "Could not create proof request.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-stack">
      <PageHeader title="Request Proof" subtitle="Ask holder only for required VC attributes." />

      <SectionCard title="New Proof Request">
        {loading ? <p className="login-muted">Loading...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        {success ? <p className="upload-success">{success}</p> : null}

        <div className="form-grid">
          <label className="field">
            <span>Holder</span>
            <select value={holderId} onChange={(event) => setHolderId(event.target.value)}>
              <option value="">Select holder</option>
              {holders.map((holder) => (
                <option key={holder.holderId} value={holder.holderId}>
                  {holder.holderWallet}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Credential</span>
            <select value={credentialId} onChange={(event) => setCredentialId(event.target.value)}>
              <option value="">Select credential</option>
              {credentials.map((credential) => (
                <option key={credential.credentialId} value={credential.credentialId}>
                  {credential.credentialId} ({credential.schema || "VerifiableCredential"})
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span>Request Expiry</span>
            <input
              type="datetime-local"
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </label>

          <label className="field">
            <span>Purpose</span>
            <input
              value={purpose}
              onChange={(event) => setPurpose(event.target.value)}
              placeholder="Why this verification is needed"
            />
          </label>
        </div>

        <label className="field" style={{ marginTop: 12 }}>
          <span>Required Fields (comma-separated paths)</span>
          <textarea
            value={requiredFields}
            onChange={(event) => setRequiredFields(event.target.value)}
            placeholder="credentialSubject.degree, credentialSubject.institution"
          />
        </label>

        <div className="helper-list">
          <p>
            Holder selected: <strong>{selectedHolder?.holderWallet || "-"}</strong>
          </p>
        </div>

        <div className="action-row" style={{ marginTop: 12 }}>
          <button type="button" className="btn btn--primary" onClick={handleSubmit} disabled={loading}>
            Send Request
          </button>
        </div>
      </SectionCard>
    </div>
  );
}
