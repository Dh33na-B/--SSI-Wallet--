import { useCallback, useEffect, useMemo, useState } from "react"
import Badge from "../../components/ui/Badge"
import DataTable from "../../components/ui/DataTable"
import PageHeader from "../../components/ui/PageHeader"
import SectionCard from "../../components/ui/SectionCard"
import { useAuth } from "../../context/AuthContext"
import { fetchRevocationHistory, mapRevocationRows, resolveAuditorId } from "./auditorData"

export default function AuditorRevocationsPage() {
  const { userId, refreshAuthSession } = useAuth()
  const [rows, setRows] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")

  const loadRevocations = useCallback(async () => {
    const auditorId = await resolveAuditorId(userId, refreshAuthSession)
    if (!auditorId) {
      setRows([])
      return
    }
    const data = await fetchRevocationHistory(auditorId)
    setRows(mapRevocationRows(data))
  }, [refreshAuthSession, userId])

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      setError("")
      try {
        await loadRevocations()
      } catch (err) {
        setError(err.message || "Failed to load revocation history.")
      } finally {
        setLoading(false)
      }
    }
    run()
  }, [loadRevocations])

  const columns = useMemo(
    () => [
      { key: "revocationId", header: "Revocation ID" },
      { key: "credentialId", header: "Credential ID" },
      { key: "issuer", header: "Issuer" },
      { key: "revokedBy", header: "Revoked By" },
      { key: "reason", header: "Reason" },
      { key: "revokedAt", header: "Revoked At" },
      { key: "chainTx", header: "Chain Tx" },
      { key: "status", header: "Status", render: (value) => <Badge value={value} /> }
    ],
    []
  )

  return (
    <div className="page-stack">
      <PageHeader title="Revocation History" subtitle="All revocation events with reason and blockchain status." />
      <SectionCard title="Revocation Ledger">
        {loading ? <p className="login-muted">Loading revocation history...</p> : null}
        {error ? <p className="login-error">{error}</p> : null}
        <DataTable columns={columns} rows={rows} />
      </SectionCard>
    </div>
  )
}
