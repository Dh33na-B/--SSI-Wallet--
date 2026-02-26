export const ROLES = {
  HOLDER: "HOLDER",
  ISSUER: "ISSUER",
  VERIFIER: "VERIFIER",
  AUDITOR: "AUDITOR"
};

export const ROLE_LABELS = {
  HOLDER: "Holder",
  ISSUER: "Issuer",
  VERIFIER: "Verifier",
  AUDITOR: "Auditor"
};

export const HOME_BY_ROLE = {
  HOLDER: "/holder/dashboard",
  ISSUER: "/issuer/dashboard",
  VERIFIER: "/verifier/dashboard",
  AUDITOR: "/auditor/dashboard"
};

export const ROLE_MENUS = {
  HOLDER: [
    { label: "Dashboard", path: "/holder/dashboard" },
    { label: "Wallet", path: "/holder/wallet" },
    { label: "Documents", path: "/holder/documents" },
    { label: "Credentials", path: "/holder/credentials" },
    { label: "Proof Requests", path: "/holder/proof-requests" },
    { label: "Proof Builder", path: "/holder/proof-builder" },
    { label: "Revocation Status", path: "/holder/revocations" },
    { label: "Settings", path: "/holder/settings" }
  ],
  ISSUER: [
    { label: "Dashboard", path: "/issuer/dashboard" },
    { label: "Submitted Documents", path: "/issuer/submissions" },
    { label: "Create VC", path: "/issuer/credentials/new" },
    { label: "Issued Credentials", path: "/issuer/credentials" },
    { label: "Anchoring", path: "/issuer/anchoring" },
    { label: "Revocations", path: "/issuer/revocations" },
    { label: "Settings", path: "/issuer/settings" }
  ],
  VERIFIER: [
    { label: "Dashboard", path: "/verifier/dashboard" },
    { label: "Request Proof", path: "/verifier/requests/new" },
    { label: "Request Queue", path: "/verifier/requests" },
    { label: "Verify Proof", path: "/verifier/verify" },
    { label: "Verification History", path: "/verifier/history" },
    { label: "Settings", path: "/verifier/settings" }
  ],
  AUDITOR: [
    { label: "Dashboard", path: "/auditor/dashboard" },
    { label: "Activity Logs", path: "/auditor/activity-logs" },
    { label: "Revocation History", path: "/auditor/revocations" },
    { label: "Proof Logs", path: "/auditor/proof-logs" },
    { label: "Suspicious Activity", path: "/auditor/alerts" },
    { label: "Analytics", path: "/auditor/analytics" },
    { label: "Reports", path: "/auditor/reports" }
  ]
};
