export default function Badge({ value }) {
  const normalized = String(value || "").toUpperCase();
  let tone = "neutral";

  if (
    ["VERIFIED", "ACTIVE", "VALID", "ANCHORED", "SIGNED", "ACCEPTED", "CONFIRMED", "LOW"].includes(normalized)
  ) {
    tone = "success";
  } else if (
    ["PENDING", "UNDER_REVIEW", "PROOF_RECEIVED", "MEDIUM", "OPEN"].includes(normalized)
  ) {
    tone = "warning";
  } else if (
    ["REJECTED", "REVOKED", "INVALID", "HIGH", "NO"].includes(normalized)
  ) {
    tone = "danger";
  }

  return <span className={`badge badge--${tone}`}>{value}</span>;
}
