import { Link } from 'react-router-dom';
import { formatNumber } from '../utils/format.js';

export default function StatCard({ label, value, to }) {
  const body = (
    <>
      <div className="stat__value">{formatNumber(value)}</div>
      <div className="stat__label">{label}</div>
    </>
  );
  return to
    ? <Link className="stat stat--link" to={to}>{body}</Link>
    : <div className="stat">{body}</div>;
}
