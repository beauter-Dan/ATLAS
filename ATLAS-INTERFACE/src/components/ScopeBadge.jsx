import Badge from './Badge.jsx';

// Anything not explicitly "in-scope" is never shown as authorized.
const MAP = {
  'in-scope': { tone: 'ok', text: 'In scope' },
  'out-of-scope': { tone: 'danger', text: 'Out of scope' },
  unverified: { tone: 'warn', text: 'Scope unverified' },
};

export default function ScopeBadge({ status }) {
  const m = MAP[status] || MAP.unverified;
  return <Badge tone={m.tone}>{m.text}</Badge>;
}
