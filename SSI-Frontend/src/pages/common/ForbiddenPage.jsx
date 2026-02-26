import { Link } from "react-router-dom";

export default function ForbiddenPage() {
  return (
    <div className="simple-page">
      <h1>403</h1>
      <p>You do not have permission to access this route with the selected role.</p>
      <Link to="/login" className="btn btn--primary">
        Back to Login
      </Link>
    </div>
  );
}
