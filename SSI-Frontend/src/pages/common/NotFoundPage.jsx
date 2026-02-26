import { Link } from "react-router-dom";

export default function NotFoundPage() {
  return (
    <div className="simple-page">
      <h1>404</h1>
      <p>The page you requested does not exist.</p>
      <Link to="/login" className="btn btn--primary">
        Go Home
      </Link>
    </div>
  );
}
