export function Loading({ label = 'Loading' }) {
  return <div className="state" role="status"><span className="spinner" aria-hidden="true" />{label}</div>;
}

export function ErrorState({ error, onRetry }) {
  return (
    <div className="state state--error" role="alert">
      <p><strong>Could not load this data.</strong></p>
      <p className="muted">{error?.message || 'Something went wrong.'}</p>
      {onRetry && <button className="btn" onClick={onRetry}>Try again</button>}
    </div>
  );
}

export function EmptyState({ title, hint, action }) {
  return (
    <div className="state">
      <p><strong>{title}</strong></p>
      {hint && <p className="muted">{hint}</p>}
      {action}
    </div>
  );
}
