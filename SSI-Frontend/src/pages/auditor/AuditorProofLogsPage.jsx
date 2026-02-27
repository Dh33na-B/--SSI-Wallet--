import { useCallback, useEffect, useMemo, useState } from "react"
import Badge from "../../components/ui/Badge"
import DataTable from "../../components/ui/DataTable"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import { useAuth } from "../../context/AuthContext"
import { fetchProofLogs, mapProofRows, resolveAuditorId } from "./auditorData"

export default function AuditorProofLogsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const loadProofLogs = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setRows([])
      return
    }
    const data = await fetchProofLogs(auditorId)
    setRows(mapProofRows(data))
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadProofLogs()
      } catch (err) {
        setError(err.message || "Failed to load proof logs.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadProofLogs])

  const columns = useMemo(
    () => [
      { key: "logId", header: "Log ID" },
      { key: "verifier", header: "Verifier" },
      { key: "credentialId", header: "Credential ID" },
      { key: "signatureResult", header: "Signature", render: (value) => <Badge value={value} /> },
      { key: "hashResult", header: "VC Hash", render: (value) => <Badge value={value} /> },
      { key: "anchoredResult", header: "Anchored", render: (value) => <Badge value={value} /> },
      { key: "revocationResult", header: "Revocation", render: (value) => <Badge value={value} /> },
      { key: "decision", header: "Decision", render: (value) => <Badge value={value} /> },
      { key: "timestamp", header: "Timestamp" }
    ],
    []
  )

  return (
    <div className="page-stack">
      <PageHeader title="Proof Verification Logs" subtitle="Traceability for every verifier decision." />
      <SectionCard title="Proof Log Table">
        {loading ? <p className="login-muted">Loading proof logs...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  )
}
