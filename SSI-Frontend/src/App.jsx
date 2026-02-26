import { Navigate, Route, Routes } from "react-router-dom";
import { HOME_BY_ROLE, ROLES } from "./config/navigation";
import { useAuth } from "./context/AuthContext";
import RoleLayout from "./layouts/RoleLayout";
import ForbiddenPage from "./pages/common/ForbiddenPage";
import LoginPage from "./pages/common/LoginPage";
import NotFoundPage from "./pages/common/NotFoundPage";
import SettingsPage from "./pages/common/SettingsPage";
import AuditorActivityLogsPage from "./pages/auditor/AuditorActivityLogsPage";
import AuditorAlertsPage from "./pages/auditor/AuditorAlertsPage";
import AuditorAnalyticsPage from "./pages/auditor/AuditorAnalyticsPage";
import AuditorDashboardPage from "./pages/auditor/AuditorDashboardPage";
import AuditorProofLogsPage from "./pages/auditor/AuditorProofLogsPage";
import AuditorReportsPage from "./pages/auditor/AuditorReportsPage";
import AuditorRevocationsPage from "./pages/auditor/AuditorRevocationsPage";
import HolderCredentialsPage from "./pages/holder/HolderCredentialsPage";
import HolderDashboardPage from "./pages/holder/HolderDashboardPage";
import HolderDocumentsPage from "./pages/holder/HolderDocumentsPage";
import HolderProofBuilderPage from "./pages/holder/HolderProofBuilderPage";
import HolderProofRequestsPage from "./pages/holder/HolderProofRequestsPage";
import HolderRevocationsPage from "./pages/holder/HolderRevocationsPage";
import HolderWalletPage from "./pages/holder/HolderWalletPage";
import IssuerAnchoringPage from "./pages/issuer/IssuerAnchoringPage";
import IssuerCredentialNewPage from "./pages/issuer/IssuerCredentialNewPage";
import IssuerCredentialsPage from "./pages/issuer/IssuerCredentialsPage";
import IssuerDashboardPage from "./pages/issuer/IssuerDashboardPage";
import IssuerRevocationsPage from "./pages/issuer/IssuerRevocationsPage";
import IssuerReviewPage from "./pages/issuer/IssuerReviewPage";
import IssuerSubmissionsPage from "./pages/issuer/IssuerSubmissionsPage";
import VerifierDashboardPage from "./pages/verifier/VerifierDashboardPage";
import VerifierHistoryPage from "./pages/verifier/VerifierHistoryPage";
import VerifierRequestNewPage from "./pages/verifier/VerifierRequestNewPage";
import VerifierRequestsPage from "./pages/verifier/VerifierRequestsPage";
import VerifierVerifyPage from "./pages/verifier/VerifierVerifyPage";

function HomeRedirect() {
  const { role, isAuthenticated } = useAuth();
  if (!isAuthenticated || !role) {
    return <Navigate to="/login" replace />;
  }
  return <Navigate to={HOME_BY_ROLE[role]} replace />;
}

function RoleGuard({ expectedRole, children }) {
  const { role, isAuthenticated } = useAuth();
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  if (role !== expectedRole) {
    return <Navigate to="/403" replace />;
  }
  return children;
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<HomeRedirect />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/403" element={<ForbiddenPage />} />

      <Route
        path="/holder"
        element={
          <RoleGuard expectedRole={ROLES.HOLDER}>
            <RoleLayout role={ROLES.HOLDER} />
          </RoleGuard>
        }
      >
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<HolderDashboardPage />} />
        <Route path="wallet" element={<HolderWalletPage />} />
        <Route path="documents" element={<HolderDocumentsPage />} />
        <Route path="credentials" element={<HolderCredentialsPage />} />
        <Route path="verification-requests" element={<HolderProofRequestsPage />} />
        <Route path="proof-requests" element={<HolderProofRequestsPage />} />
        <Route path="proof-builder" element={<HolderProofBuilderPage />} />
        <Route path="revocations" element={<HolderRevocationsPage />} />
        <Route path="settings" element={<SettingsPage role="Holder" />} />
      </Route>

      <Route
        path="/issuer"
        element={
          <RoleGuard expectedRole={ROLES.ISSUER}>
            <RoleLayout role={ROLES.ISSUER} />
          </RoleGuard>
        }
      >
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<IssuerDashboardPage />} />
        <Route path="submissions" element={<IssuerSubmissionsPage />} />
        <Route path="review/:documentId" element={<IssuerReviewPage />} />
        <Route path="credentials/new" element={<IssuerCredentialNewPage />} />
        <Route path="credentials" element={<IssuerCredentialsPage />} />
        <Route path="anchoring" element={<IssuerAnchoringPage />} />
        <Route path="revocations" element={<IssuerRevocationsPage />} />
        <Route path="settings" element={<SettingsPage role="Issuer" />} />
      </Route>

      <Route
        path="/verifier"
        element={
          <RoleGuard expectedRole={ROLES.VERIFIER}>
            <RoleLayout role={ROLES.VERIFIER} />
          </RoleGuard>
        }
      >
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<VerifierDashboardPage />} />
        <Route path="requests/new" element={<VerifierRequestNewPage />} />
        <Route path="requests" element={<VerifierRequestsPage />} />
        <Route path="verify" element={<VerifierVerifyPage />} />
        <Route path="history" element={<VerifierHistoryPage />} />
        <Route path="settings" element={<SettingsPage role="Verifier" />} />
      </Route>

      <Route
        path="/auditor"
        element={
          <RoleGuard expectedRole={ROLES.AUDITOR}>
            <RoleLayout role={ROLES.AUDITOR} />
          </RoleGuard>
        }
      >
        <Route index element={<Navigate to="dashboard" replace />} />
        <Route path="dashboard" element={<AuditorDashboardPage />} />
        <Route path="activity-logs" element={<AuditorActivityLogsPage />} />
        <Route path="revocations" element={<AuditorRevocationsPage />} />
        <Route path="proof-logs" element={<AuditorProofLogsPage />} />
        <Route path="alerts" element={<AuditorAlertsPage />} />
        <Route path="analytics" element={<AuditorAnalyticsPage />} />
        <Route path="reports" element={<AuditorReportsPage />} />
      </Route>

      <Route path="*" element={<NotFoundPage />} />
    </Routes>
  );
}
