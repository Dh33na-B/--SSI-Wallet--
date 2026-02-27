import { useCallback, useEffect, useMemo, useState } from "react"
import Badge from "../../components/ui/Badge"
import DataTable from "../../components/ui/DataTable"
import Modal from "../../components/ui/Modal"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import { useAuth } from "../../context/AuthContext"
import {
  deriveSuspiciousAlerts,
  loadAuditorCollections,
  mapActivityRows,
  mapProofRows,
  mapRevocationRows,
  resolveAuditorId
} from "./auditorData"

export default function AuditorAlertsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [open, setOpen] = useState(false)
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [escalationNote, setEscalationNote] = useState("")

  const loadAlerts = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setRows([])
      return
    }
    const { activityLogs, revocations, proofLogs } = await loadAuditorCollections(auditorId)
    const alerts = deriveSuspiciousAlerts({
      activityRows: mapActivityRows(activityLogs),
      revocationRows: mapRevocationRows(revocations),
      proofRows: mapProofRows(proofLogs)
    })
    setRows(alerts)
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadAlerts()
      } catch (err) {
        setError(err.message || "Failed to load alerts.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadAlerts])

  const markInvestigated = (alertId) => {
    setRows((previous) =>
      previous.map((row) => (row.id === alertId ? { ...row, status: "INVESTIGATED" } : row))
    )
  }

  const columns = useMemo(
    () => [
      { key: "id", header: "Alert ID" },
      { key: "severity", header: "Severity", render: (value) => <Badge value={value} /> },
      { key: "summary", header: "Summary" },
      { key: "impactedEntity", header: "Impacted Entity" },
      { key: "createdAt", header: "Created At" },
      { key: "status", header: "Status", render: (value) => <Badge value={value} /> },
      {
        key: "actions",
        header: "Actions",
        render: (_, row) => (
          <div className="action-row">
            <button type="button" className="btn btn--secondary" onClick={() => markInvestigated(row.id)}>
              Mark Investigated
            </button>
            <button type="button" className="btn btn--danger" onClick={() => setOpen(true)}>
              Escalate
            </button>
          </div>
        )
      }
    ],
    []
  )

  return (
    <div className="page-stack">
      <PageHeader title="Suspicious Activity" subtitle="Risk alerts and escalation console." />
      <SectionCard title="Alert Queue">
        {loading ? <p className="login-muted">Loading alerts...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>

      <Modal
        open={open}
        title="Escalate Alert"
        onClose={() => setOpen(false)}
        footer={
          <>
            <button type="button" className="btn btn--ghost" onClick={() => setOpen(false)}>
              Cancel
            </button>
            <button
              type="button"
              className="btn btn--danger"
              onClick={() => {
                setOpen(false)
                setEscalationNote("")
              }}
            >
              Escalate
            </button>
          </>
        }
      >
        <label className="field">
          <span>Escalation Note</span>
          <textarea
            placeholder="Provide incident context and recommended action..."
            value={escalationNote}
            onChange={(event) => setEscalationNote(event.target.value)}
          />
        </label>
      </Modal>
    </div>
  )
}
