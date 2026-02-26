import { NavLink, Outlet } from "react-router-dom";
import { ROLE_LABELS, ROLE_MENUS } from "../config/navigation";
import { useAuth } from "../context/AuthContext";

function MenuItem({ item }) {
  return (
    <NavLink
      to={item.path}
      className={({ isActive }) => `sidebar-link ${isActive ? "sidebar-link--active" : ""}`}
    >
      {item.label}
    </NavLink>
  );
}

export default function RoleLayout({ role }) {
  const { walletAddress, disconnectWallet } = useAuth();
  const menu = ROLE_MENUS[role] || [];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-dot" />
          <div>
            <p className="brand-title">SSI Workspace</p>
            <p className="brand-subtitle">{ROLE_LABELS[role]} Portal</p>
          </div>
        </div>
        <nav className="sidebar-nav">
          {menu.map((item) => (
            <MenuItem key={item.path} item={item} />
          ))}
        </nav>
      </aside>

      <div className="app-main">
        <header className="topbar">
          <div className="topbar-meta">
            <span className="role-pill">{ROLE_LABELS[role]}</span>
            <span className="wallet-pill">Wallet: {walletAddress || "Not connected"}</span>
          </div>
          <button type="button" className="btn btn--danger" onClick={disconnectWallet}>
            Disconnect
          </button>
        </header>

        <main className="content-area">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
