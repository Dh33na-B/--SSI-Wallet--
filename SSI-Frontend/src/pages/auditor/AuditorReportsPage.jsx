import { useCallback, useEffect, useState } from "react"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import { useAuth } from "../../context/AuthContext"
import {
  computeAnalytics,
  downloadTextFile,
  exportAuditorCsv,
  loadAuditorCollections,
  mapActivityRows,
  mapProofRows,
  mapRevocationRows,
  resolveAuditorId
} from "./auditorData"

const getTimestamp = () => {
  const now = new Date()
  const date = now.toISOString().slice(0, 19).replace(/[:T]/g, "-")
  return date
}

export default function AuditorReportsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [activityRows, setActivityRows] = useState([])
  const [revocationRows, setRevocationRows] = useState([])
  const [proofRows, setProofRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const loadData = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setActivityRows([])
      setRevocationRows([])
      setProofRows([])
      return
    }

    const { activityLogs, revocations, proofLogs } = await loadAuditorCollections(auditorId)
    setActivityRows(mapActivityRows(activityLogs))
    setRevocationRows(mapRevocationRows(revocations))
    setProofRows(mapProofRows(proofLogs))
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadData()
      } catch (err) {
        setError(err.message || "Failed to load report sources.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadData])

  const analytics = computeAnalytics({ activityRows, revocationRows, proofRows })

  const generateCsv = () => {
    const csv = exportAuditorCsv({ activityRows, revocationRows, proofRows })
    downloadTextFile(`auditor-report-${getTimestamp()}.csv`, csv, "text/csv;charset=utf-8")
  }

  const generateJson = () => {
    const payload = {
      generatedAt: new Date().toISOString(),
      analytics,
      activityLogs: activityRows,
      revocationHistory: revocationRows,
      proofLogs: proofRows
    }
    downloadTextFile(`auditor-report-${getTimestamp()}.json`, JSON.stringify(payload, null, 2), "application/json;charset=utf-8")
  }

  return (
    <div className="page-stack">
      <PageHeader title="Reports" subtitle="Generate compliance exports for review boards." />

      <SectionCard title="Report Snapshot">
        {loading ? <p className="login-muted">Loading report data...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <div className="helper-list">
          <p>Total activity events: {analytics.activityTotal}</p>
          <p>Total revocations: {analytics.revocationsTotal}</p>
          <p>Total proof logs: {analytics.proofTotal}</p>
          <p>Proof success rate: {analytics.proofSuccessRate}%</p>
        </div>
      </SectionCard>

      <SectionCard title="Export Options">
        <div className="action-row">
          <button type="button" className="btn btn--secondary" onClick={generateCsv} disabled={loading}>
            Generate CSV
          </button>
          <button type="button" className="btn btn--primary" onClick={generateJson} disabled={loading}>
            Generate JSON
          </button>
        </div>
      </SectionCard>
    </div>
  )
}
