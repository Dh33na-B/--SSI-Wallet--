import { useCallback, useEffect, useMemo, useState } from "react"
import DataTable from "../../components/ui/DataTable"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import { useAuth } from "../../context/AuthContext"
import { fetchActivityLogs, mapActivityRows, resolveAuditorId } from "./auditorData"

const ROLE_OPTIONS = ["ALL", "USER", "ISSUER", "VERIFIER", "AUDITOR"]

export default function AuditorActivityLogsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [fromDate, setFromDate] = useState("")
  const [roleFilter, setRoleFilter] = useState("ALL")
  const [actionFilter, setActionFilter] = useState("")

  const loadLogs = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setRows([])
      return
    }
    const data = await fetchActivityLogs(auditorId)
    setRows(mapActivityRows(data))
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadLogs()
      } catch (err) {
        setError(err.message || "Failed to load activity logs.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadLogs])

  const filteredRows = useMemo(() => {
    return rows.filter((row) => {
      if (roleFilter !== "ALL" && String(row.actorRole || "").toUpperCase() !== roleFilter) {
        return false
      }
      if (actionFilter && !String(row.action || "").toUpperCase().includes(actionFilter.toUpperCase())) {
        return false
      }
      if (fromDate) {
        const rowDate = row.rawTimestamp ? new Date(row.rawTimestamp) : null
        if (!rowDate || Number.isNaN(rowDate.getTime())) {
          return false
        }
        const dayStart = new Date(fromDate)
        if (Number.isNaN(dayStart.getTime()) || rowDate < dayStart) {
          return false
        }
      }
      return true
    })
  }, [actionFilter, fromDate, roleFilter, rows])

  const columns = useMemo(
    () => [
      { key: "eventId", header: "Event ID" },
      { key: "actorRole", header: "Actor Role" },
      { key: "actorId", header: "Actor ID" },
      { key: "action", header: "Action" },
      { key: "entityType", header: "Entity Type" },
      { key: "entityId", header: "Entity ID" },
      { key: "timestamp", header: "Timestamp" }
    ],
    []
  )

  return (
    <div className="page-stack">
      <PageHeader title="System Activity Logs" subtitle="Comprehensive event stream for compliance tracing." />
      <SectionCard title="Log Explorer">
        <div className="form-grid" style={{ marginBottom: 12 }}>
          <label className="field">
            <span>From Date</span>
            <input type="date" value={fromDate} onChange={(event) => setFromDate(event.target.value)} />
          </label>
          <label className="field">
            <span>Role Filter</span>
            <select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value)}>
              {ROLE_OPTIONS.map((option) => (
                <option key={option} value={option}>
                  {option === "ALL" ? "All Roles" : option}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Action Filter</span>
            <input
              placeholder="VERIFY_DOCUMENT"
              value={actionFilter}
              onChange={(event) => setActionFilter(event.target.value)}
            />
          </label>
        </div>
        {loading ? <p className="login-muted">Loading activity logs...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={filteredRows} />
      </SectionCard>
    </div>
  )
}
