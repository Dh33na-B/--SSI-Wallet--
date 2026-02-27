const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8080"

const DAY_MS = 24 * 60 * 60 * 1000

const parseApiError = async (response, fallback) => {
  try {
    const data = await response.json()
    if (data?.message) {
      return data.message
    }
  } catch {
    // ignore parse failures
  }
  return fallback
}

const parseTime = (value) => {
  if (!value) {
    return 0
  }
  const parsed = new Date(value).getTime()
  return Number.isFinite(parsed) ? parsed : 0
}

export const formatDateTime = (value) => {
  if (!value) {
    return "-"
  }
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return "-"
  }
  return parsed.toLocaleString()
}

export const shortText = (value, max = 22) => {
  if (!value) {
    return "-"
  }
  const text = String(value)
  if (text.length <= max) {
    return text
  }
  return `${text.slice(0, 8)}...${text.slice(-6)}`
}

const boolLabel = (value, trueLabel, falseLabel) => {
  if (value === true) {
    return trueLabel
  }
  if (value === false) {
    return falseLabel
  }
  return "-"
}

const toArray = (value) => (Array.isArray(value) ? value : [])

const fetchAuditorResource = async (auditorId, path, fallbackMessage) => {
  const response = await fetch(`${API_BASE_URL}/api/auditor/${auditorId}/${path}`)
  if (!response.ok) {
    throw new Error(await parseApiError(response, fallbackMessage))
  }
  return toArray(await response.json())
}

export const resolveAuditorId = async (userId, refreshAuthSession) => {
  if (userId) {
    return userId
  }
  return (await refreshAuthSession()) || ""
}

export const fetchActivityLogs = async (auditorId) =>
  fetchAuditorResource(auditorId, "logs/audit", "Could not load activity logs.")

export const fetchRevocationHistory = async (auditorId) =>
  fetchAuditorResource(auditorId, "logs/revocations", "Could not load revocation history.")

export const fetchProofLogs = async (auditorId) =>
  fetchAuditorResource(auditorId, "logs/proofs", "Could not load proof logs.")

export const loadAuditorCollections = async (auditorId) => {
  const [activityLogs, revocations, proofLogs] = await Promise.all([
    fetchActivityLogs(auditorId),
    fetchRevocationHistory(auditorId),
    fetchProofLogs(auditorId)
  ])

  return {
    activityLogs,
    revocations,
    proofLogs
  }
}

export const mapActivityRows = (items) =>
  toArray(items).map((item) => ({
    id: item?.id || "",
    eventId: shortText(item?.id || "-", 20),
    actorRole: item?.user?.role || "-",
    actorId: shortText(item?.user?.walletAddress || item?.user?.id || "-", 24),
    action: item?.actionType || "-",
    entityType: item?.entityType || "-",
    entityId: item?.entityId || "-",
    timestamp: formatDateTime(item?.createdAt),
    rawTimestamp: parseTime(item?.createdAt)
  }))

export const mapRevocationRows = (items) =>
  toArray(items).map((item) => ({
    id: item?.id || "",
    revocationId: shortText(item?.id || "-", 20),
    credentialId: item?.credential?.credentialId || "-",
    issuer: shortText(item?.credential?.issuer?.walletAddress || "-", 24),
    revokedBy: shortText(item?.revokedBy?.walletAddress || item?.revokedBy?.id || "-", 24),
    reason: item?.reason || "-",
    revokedAt: formatDateTime(item?.revokedAt),
    chainTx: shortText(item?.credential?.blockchainTxHash || "-", 24),
    status: item?.credential?.revoked ? "CONFIRMED" : "ACTIVE",
    rawTimestamp: parseTime(item?.revokedAt)
  }))

export const mapProofRows = (items) =>
  toArray(items).map((item) => ({
    id: item?.id || "",
    logId: shortText(item?.id || "-", 20),
    verifier: shortText(item?.verifier?.walletAddress || item?.verifier?.id || "-", 24),
    credentialId: item?.credential?.credentialId || "-",
    signatureResult: boolLabel(item?.signatureValid, "VALID", "INVALID"),
    hashResult: boolLabel(item?.vcHashMatches, "MATCH", "MISMATCH"),
    anchoredResult: boolLabel(item?.blockchainAnchored, "ANCHORED", "MISSING"),
    revocationResult:
      item?.blockchainRevoked === true ? "REVOKED" : item?.blockchainRevoked === false ? "NOT_REVOKED" : "-",
    decision: item?.verificationStatus === true ? "VALID" : item?.verificationStatus === false ? "INVALID" : "PENDING",
    notes: item?.notes || "-",
    timestamp: formatDateTime(item?.verifiedAt),
    rawTimestamp: parseTime(item?.verifiedAt)
  }))

export const deriveSuspiciousAlerts = ({ activityRows, revocationRows, proofRows }) => {
  const now = Date.now()
  const invalidProofs24h = proofRows.filter(
    (row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS && row.decision === "INVALID"
  ).length
  const revocations24h = revocationRows.filter((row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS).length
  const recentActivity = activityRows.some((row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS)

  const alerts = []
  if (invalidProofs24h >= 3) {
    alerts.push({
      id: `ALERT-${alerts.length + 1}`,
      severity: "HIGH",
      summary: `${invalidProofs24h} invalid proof verifications in last 24h.`,
      impactedEntity: "VERIFIER_FLOW",
      createdAt: new Date().toLocaleString(),
      status: "OPEN"
    })
  }
  if (revocations24h >= 2) {
    alerts.push({
      id: `ALERT-${alerts.length + 1}`,
      severity: "HIGH",
      summary: `${revocations24h} credential revocations in last 24h.`,
      impactedEntity: "ISSUER_FLOW",
      createdAt: new Date().toLocaleString(),
      status: "OPEN"
    })
  }
  if (!recentActivity) {
    alerts.push({
      id: `ALERT-${alerts.length + 1}`,
      severity: "MEDIUM",
      summary: "No audit activity observed in last 24h.",
      impactedEntity: "AUDIT_STREAM",
      createdAt: new Date().toLocaleString(),
      status: "OPEN"
    })
  }

  if (alerts.length === 0) {
    alerts.push({
      id: "ALERT-0",
      severity: "LOW",
      summary: "No suspicious behavior detected from current logs.",
      impactedEntity: "SYSTEM",
      createdAt: new Date().toLocaleString(),
      status: "OPEN"
    })
  }

  return alerts
}

export const computeAnalytics = ({ activityRows, revocationRows, proofRows }) => {
  const now = Date.now()
  const activity24h = activityRows.filter((row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS).length
  const revocations24h = revocationRows.filter((row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS).length
  const proof24h = proofRows.filter((row) => row.rawTimestamp > 0 && now - row.rawTimestamp <= DAY_MS).length
  const proofValid = proofRows.filter((row) => row.decision === "VALID").length
  const proofInvalid = proofRows.filter((row) => row.decision === "INVALID").length
  const proofTotal = proofRows.length
  const proofSuccessRate = proofTotal === 0 ? 0 : Math.round((proofValid / proofTotal) * 100)

  return {
    activityTotal: activityRows.length,
    activity24h,
    revocationsTotal: revocationRows.length,
    revocations24h,
    proofTotal,
    proof24h,
    proofValid,
    proofInvalid,
    proofSuccessRate
  }
}

const escapeCsvValue = (value) => {
  const text = String(value ?? "")
  if (text.includes(",") || text.includes("\"") || text.includes("\n")) {
    return `"${text.replace(/\"/g, "\"\"")}"`
  }
  return text
}

const rowsToCsv = (rows, columns) => {
  const header = columns.map((column) => escapeCsvValue(column.header)).join(",")
  const data = rows.map((row) => columns.map((column) => escapeCsvValue(row[column.key] ?? "")).join(","))
  return [header, ...data].join("\n")
}

export const downloadTextFile = (fileName, content, mimeType = "text/plain;charset=utf-8") => {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement("a")
  anchor.href = url
  anchor.download = fileName
  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()
  URL.revokeObjectURL(url)
}

export const exportAuditorCsv = ({ activityRows, revocationRows, proofRows }) => {
  const activityCsv = rowsToCsv(activityRows, [
    { key: "eventId", header: "Event ID" },
    { key: "actorRole", header: "Actor Role" },
    { key: "actorId", header: "Actor ID" },
    { key: "action", header: "Action" },
    { key: "entityType", header: "Entity Type" },
    { key: "entityId", header: "Entity ID" },
    { key: "timestamp", header: "Timestamp" }
  ])
  const revocationCsv = rowsToCsv(revocationRows, [
    { key: "revocationId", header: "Revocation ID" },
    { key: "credentialId", header: "Credential ID" },
    { key: "issuer", header: "Issuer" },
    { key: "revokedBy", header: "Revoked By" },
    { key: "reason", header: "Reason" },
    { key: "revokedAt", header: "Revoked At" },
    { key: "chainTx", header: "Chain Tx" },
    { key: "status", header: "Status" }
  ])
  const proofCsv = rowsToCsv(proofRows, [
    { key: "logId", header: "Log ID" },
    { key: "verifier", header: "Verifier" },
    { key: "credentialId", header: "Credential ID" },
    { key: "signatureResult", header: "Signature" },
    { key: "hashResult", header: "VC Hash" },
    { key: "anchoredResult", header: "Anchored" },
    { key: "revocationResult", header: "Revocation" },
    { key: "decision", header: "Decision" },
    { key: "timestamp", header: "Timestamp" }
  ])

  return [
    "Activity Logs",
    activityCsv,
    "",
    "Revocation History",
    revocationCsv,
    "",
    "Proof Logs",
    proofCsv
  ].join("\n")
}

export const buildPdfHtml = ({ analytics, activityRows, revocationRows, proofRows }) => {
  const now = new Date().toLocaleString()
  const topActivity = activityRows.slice(0, 12)
  const topRevocations = revocationRows.slice(0, 12)
  const topProofs = proofRows.slice(0, 12)

  const renderTable = (title, headers, rows) => {
    const headerRow = headers.map((header) => `<th>${header}</th>`).join("")
    const bodyRows = rows
      .map(
        (row) => `<tr>${Object.values(row)
          .map((value) => `<td>${String(value ?? "-")}</td>`)
          .join("")}</tr>`
      )
      .join("")
    return `
      <h3>${title}</h3>
      <table>
        <thead><tr>${headerRow}</tr></thead>
        <tbody>${bodyRows || `<tr><td colspan="${headers.length}">No records</td></tr>`}</tbody>
      </table>
    `
  }

  return `
    <html>
      <head>
        <title>SSI Auditor Report</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 24px; color: #1b1530; }
          h1 { margin: 0 0 8px 0; }
          .meta { color: #5d5678; margin-bottom: 18px; }
          .stats { margin-bottom: 20px; }
          .stats p { margin: 4px 0; }
          h3 { margin: 22px 0 8px 0; }
          table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 12px; }
          th, td { border: 1px solid #d9d1ef; padding: 6px; text-align: left; vertical-align: top; }
          th { background: #f4f1ff; }
        </style>
      </head>
      <body>
        <h1>SSI Compliance Report</h1>
        <div class="meta">Generated at: ${now}</div>
        <div class="stats">
          <p>Total activity events: ${analytics.activityTotal} (24h: ${analytics.activity24h})</p>
          <p>Total revocations: ${analytics.revocationsTotal} (24h: ${analytics.revocations24h})</p>
          <p>Total proof logs: ${analytics.proofTotal} (24h: ${analytics.proof24h})</p>
          <p>Proof success rate: ${analytics.proofSuccessRate}%</p>
        </div>
        ${renderTable(
          "Recent Activity",
          ["Event ID", "Role", "Actor", "Action", "Entity", "Entity ID", "Timestamp"],
          topActivity.map((row) => ({
            eventId: row.eventId,
            actorRole: row.actorRole,
            actorId: row.actorId,
            action: row.action,
            entityType: row.entityType,
            entityId: row.entityId,
            timestamp: row.timestamp
          }))
        )}
        ${renderTable(
          "Recent Revocations",
          ["Revocation ID", "Credential", "Issuer", "Revoked By", "Reason", "Revoked At", "Status"],
          topRevocations.map((row) => ({
            revocationId: row.revocationId,
            credentialId: row.credentialId,
            issuer: row.issuer,
            revokedBy: row.revokedBy,
            reason: row.reason,
            revokedAt: row.revokedAt,
            status: row.status
          }))
        )}
        ${renderTable(
          "Recent Proof Logs",
          ["Log ID", "Verifier", "Credential", "Signature", "Hash", "Anchored", "Revocation", "Decision", "Timestamp"],
          topProofs.map((row) => ({
            logId: row.logId,
            verifier: row.verifier,
            credentialId: row.credentialId,
            signatureResult: row.signatureResult,
            hashResult: row.hashResult,
            anchoredResult: row.anchoredResult,
            revocationResult: row.revocationResult,
            decision: row.decision,
            timestamp: row.timestamp
          }))
        )}
      </body>
    </html>
  `
}
