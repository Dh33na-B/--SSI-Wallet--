export const holderDocuments = [
  {
    id: "DOC-1021",
    fileName: "passport.pdf",
    uploadedOn: "2026-02-20",
    ipfsCid: "bafybeic94...m1z",
    status: "VERIFIED",
    issuer: "City KYC Board",
    lastUpdated: "2026-02-23"
  },
  {
    id: "DOC-1044",
    fileName: "degree.pdf",
    uploadedOn: "2026-02-24",
    ipfsCid: "bafybeif48...k3x",
    status: "PENDING",
    issuer: "UniChain Institute",
    lastUpdated: "2026-02-25"
  }
];

export const holderCredentials = [
  {
    id: "VC-ENG-2026-001",
    issuer: "UniChain Institute",
    type: "DegreeCredential",
    issuedDate: "2026-01-12",
    expiry: "2029-01-12",
    revocationStatus: "ACTIVE",
    blockchainTx: "0x8c43...9af2",
    fields: ["fullName", "degree", "major", "graduationYear", "cgpa", "dob"]
  },
  {
    id: "VC-KYC-2026-116",
    issuer: "City KYC Board",
    type: "KycCredential",
    issuedDate: "2026-02-14",
    expiry: "2028-02-14",
    revocationStatus: "ACTIVE",
    blockchainTx: "0x2d71...f77a",
    fields: ["fullName", "nationality", "dob", "idNumber"]
  }
];

export const holderProofRequests = [
  {
    id: "REQ-3321",
    verifier: "Acme Hiring",
    requestedFields: "fullName, degree, graduationYear",
    requestedAt: "2026-02-24 10:30",
    expiry: "2026-02-28 23:59",
    status: "PENDING"
  },
  {
    id: "REQ-3322",
    verifier: "BankOne",
    requestedFields: "fullName, nationality",
    requestedAt: "2026-02-23 08:22",
    expiry: "2026-02-25 23:59",
    status: "ACCEPTED"
  }
];

export const issuerSubmissions = [
  {
    id: "DOC-1021",
    holderWallet: "0x15a...90c2",
    documentType: "Passport",
    submittedAt: "2026-02-20 09:00",
    status: "UNDER_REVIEW"
  },
  {
    id: "DOC-1044",
    holderWallet: "0x22f...77e0",
    documentType: "Degree",
    submittedAt: "2026-02-24 14:40",
    status: "PENDING"
  }
];

export const issuedCredentials = [
  {
    credentialId: "VC-KYC-7781",
    holder: "0x15a...90c2",
    schema: "KYC v2",
    signedStatus: "SIGNED",
    anchoredStatus: "ANCHORED",
    txHash: "0x6f12...82ce",
    revoked: "NO",
    issuedAt: "2026-02-19"
  },
  {
    credentialId: "VC-EMP-8122",
    holder: "0x98b...02fa",
    schema: "Employment v1",
    signedStatus: "DRAFT",
    anchoredStatus: "PENDING",
    txHash: "-",
    revoked: "NO",
    issuedAt: "2026-02-25"
  }
];

export const verifierRequests = [
  {
    id: "REQ-9210",
    holderWallet: "0x15a...90c2",
    requestedFields: "fullName, degree",
    sentAt: "2026-02-25 11:12",
    expiry: "2026-02-28 23:59",
    status: "PROOF_RECEIVED"
  },
  {
    id: "REQ-9213",
    holderWallet: "0x98b...02fa",
    requestedFields: "fullName, employer",
    sentAt: "2026-02-26 08:05",
    expiry: "2026-03-01 23:59",
    status: "PENDING"
  }
];

export const verifierHistory = [
  {
    verificationId: "VER-5002",
    credentialId: "VC-ENG-2026-001",
    holder: "0x15a...90c2",
    signatureResult: "VALID",
    revocationResult: "NOT_REVOKED",
    finalDecision: "ACCEPTED",
    verifiedAt: "2026-02-25 12:01"
  },
  {
    verificationId: "VER-5005",
    credentialId: "VC-KYC-2026-116",
    holder: "0x11c...ee12",
    signatureResult: "VALID",
    revocationResult: "REVOKED",
    finalDecision: "REJECTED",
    verifiedAt: "2026-02-26 09:41"
  }
];

export const auditActivityLogs = [
  {
    eventId: "LOG-10011",
    actorRole: "ISSUER",
    actorId: "0xissuer...31",
    action: "VERIFY_DOCUMENT",
    entityType: "DOCUMENT",
    entityId: "DOC-1044",
    timestamp: "2026-02-26 09:40",
    device: "Chrome / Win11"
  },
  {
    eventId: "LOG-10012",
    actorRole: "VERIFIER",
    actorId: "0xverify...84",
    action: "VERIFY_CREDENTIAL",
    entityType: "CREDENTIAL",
    entityId: "VC-KYC-7781",
    timestamp: "2026-02-26 09:43",
    device: "Firefox / Ubuntu"
  }
];

export const auditRevocations = [
  {
    revocationId: "RVK-112",
    credentialId: "VC-KYC-5501",
    issuer: "0xissuer...31",
    reason: "Document tampering",
    revokedAt: "2026-02-24 15:12",
    chainTx: "0x9bce...af71",
    status: "CONFIRMED"
  }
];

export const auditProofLogs = [
  {
    logId: "PLOG-902",
    verifier: "0xverify...84",
    credentialId: "VC-ENG-2026-001",
    signatureResult: "VALID",
    revocationResult: "NOT_REVOKED",
    decision: "ACCEPTED",
    timestamp: "2026-02-26 09:45"
  }
];

export const suspiciousAlerts = [
  {
    id: "ALERT-08",
    severity: "MEDIUM",
    summary: "Verifier rejection rate rose to 82% in last 24h",
    impactedEntity: "VERIFIER:0xverify...84",
    createdAt: "2026-02-26 09:55",
    status: "OPEN"
  },
  {
    id: "ALERT-09",
    severity: "HIGH",
    summary: "Issuer attempted 3 rapid revocations in 2 minutes",
    impactedEntity: "ISSUER:0xissuer...31",
    createdAt: "2026-02-26 10:02",
    status: "OPEN"
  }
];
