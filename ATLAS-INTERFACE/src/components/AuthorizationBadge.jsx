import Badge from './Badge.jsx';

// Only "authorized" is ever shown as a positive state.
const MAP = {
  authorized: { tone: 'ok', text: 'Authorized' },
  pending: { tone: 'warn', text: 'Pending authorization' },
  expired: { tone: 'danger', text: 'Authorization expired' },
  revoked: { tone: 'danger', text: 'Authorization revoked' },
};

export default function AuthorizationBadge({ status }) {
  const m = MAP[status] || MAP.pending;
  return <Badge tone={m.tone}>{m.text}</Badge>;
}
