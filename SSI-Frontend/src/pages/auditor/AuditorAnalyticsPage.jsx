import { useCallback, useEffect, useMemo, useState } from "react"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import StatCard from "../../components/ui/StatCard"
import { useAuth } from "../../context/AuthContext"
import {
  computeAnalytics,
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

export default function AuditorAnalyticsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [analytics, setAnalytics] = useState(EMPTY_ANALYTICS)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const loadAnalytics = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setAnalytics(EMPTY_ANALYTICS)
      return
    }

    const { activityLogs, revocations, proofLogs } = await loadAuditorCollections(auditorId)
    const computed = computeAnalytics({
      activityRows: mapActivityRows(activityLogs),
      revocationRows: mapRevocationRows(revocations),
      proofRows: mapProofRows(proofLogs)
    })
    setAnalytics(computed)
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadAnalytics()
      } catch (err) {
        setError(err.message || "Failed to load analytics.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadAnalytics])

  const metrics = useMemo(
    () => [
      { label: "Activity Events (24h)", value: analytics.activity24h, scale: "count" },
      { label: "Revocations (24h)", value: analytics.revocations24h, scale: "count" },
      { label: "Proof Checks (24h)", value: analytics.proof24h, scale: "count" },
      { label: "Proof Success Rate", value: analytics.proofSuccessRate, scale: "percent" }
    ],
    [analytics]
  )

  return (
    <div className="page-stack">
      <PageHeader title="Analytics Dashboard" subtitle="Operational and compliance trend monitoring." />

      {loading ? <p className="login-muted">Loading analytics...</p> : null}
      {error ? <p className="login-error">{error}</p> : null}

      <div className="stats-grid">
        <StatCard label="Total Activity" value={analytics.activityTotal} trend={`24h: ${analytics.activity24h}`} />
        <StatCard label="Total Revocations" value={analytics.revocationsTotal} trend={`24h: ${analytics.revocations24h}`} />
        <StatCard label="Proof Logs" value={analytics.proofTotal} trend={`Valid: ${analytics.proofValid} / Invalid: ${analytics.proofInvalid}`} />
        <StatCard label="Proof Success Rate" value={`${analytics.proofSuccessRate}%`} trend="Across all proof logs" />
      </div>

      <SectionCard title="Event Distribution">
        <div className="chart-row">
          {metrics.map((metric) => (
            <div key={metric.label} className="chart-bar">
              <strong>{metric.label}</strong>
              <div
                className="chart-fill"
                style={{
                  width: `${Math.max(
                    8,
                    Math.min(
                      100,
                      metric.scale === "percent" ? metric.value : metric.value * 10
                    )
                  )}%`
                }}
              />
              <span>{metric.scale === "percent" ? `${metric.value}%` : metric.value}</span>
            </div>
          ))}
        </div>
      </SectionCard>
    </div>
  )
}
