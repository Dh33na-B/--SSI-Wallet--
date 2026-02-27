import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import StatCard from "../../components/ui/StatCard"
import { useAuth } from "../../context/AuthContext"
import {
  computeAnalytics,
  deriveSuspiciousAlerts,
  loadAuditorCollections,
  mapActivityRows,
  mapProofRows,
  mapRevocationRows,
  resolveAuditorId
} from "./auditorData"

const EMPTY_ANALYTICS = {
  activityTotal: 0,
  activity24h: 0,
  revocationsTotal: 0,
  revocations24h: 0,
  proofTotal: 0,
  proof24h: 0,
  proofValid: 0,
  proofInvalid: 0,
  proofSuccessRate: 0
}

export default function AuditorDashboardPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [analytics, setAnalytics] = useState(EMPTY_ANALYTICS)
  const [alertCount, setAlertCount] = useState(0)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const loadDashboard = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setAnalytics(EMPTY_ANALYTICS)
      setAlertCount(0)
      return
    }

    const { activityLogs, revocations, proofLogs } = await loadAuditorCollections(auditorId)
    const activityRows = mapActivityRows(activityLogs)
    const revocationRows = mapRevocationRows(revocations)
    const proofRows = mapProofRows(proofLogs)
    const metrics = computeAnalytics({ activityRows, revocationRows, proofRows })
    const alerts = deriveSuspiciousAlerts({ activityRows, revocationRows, proofRows })

    setAnalytics(metrics)
    setAlertCount(alerts.length)
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadDashboard()
      } catch (err) {
        setError(err.message || "Failed to load auditor dashboard.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadDashboard])

  return (
    <div className="page-stack">
      <PageHeader title="Auditor Dashboard" subtitle="Read-only compliance view across activity, revocations, and proofs." />

      {loading ? <p className="login-muted">Loading dashboard...</p> : null}
      {error ? <p className="login-error">{error}</p> : null}

      <div className="stats-grid">
        <StatCard label="Activity Events" value={analytics.activityTotal} trend={`Last 24h: ${analytics.activity24h}`} />
        <StatCard label="Revocations" value={analytics.revocationsTotal} trend={`Last 24h: ${analytics.revocations24h}`} />
        <StatCard label="Proof Logs" value={analytics.proofTotal} trend={`Success: ${analytics.proofSuccessRate}%`} />
        <StatCard label="Suspicious Alerts" value={alertCount} trend={alertCount > 0 ? "Monitor risk signals" : "No active alerts"} />
      </div>

      <SectionCard title="Security Boundaries">
        <ul className="helper-list">
          <li>Auditor cannot revoke credentials, sign VC, or request proofs.</li>
          <li>Auditor cannot access private keys or decrypted document payloads.</li>
          <li>Audit screens must remain immutable except review annotations.</li>
        </ul>
      </SectionCard>
    </div>
  )
}
