import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import AuthorizationBadge from '../components/AuthorizationBadge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { listTargets } from '../services/targetService.js';
import { effectiveAuthorization } from '../utils/scope.js';
import { hasRole } from '../utils/roles.js';
import { formatDate } from '../utils/format.js';

const FILTERS = [['all', 'All statuses'], ['authorized', 'Authorized'], ['pending', 'Pending'], ['expired', 'Expired']];

export default function TargetsPage() {
  const { user } = useAuth();
  const { data, loading, error, reload } = useApi(listTargets);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');
  const canRegister = hasRole(user, 'analyst');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data || [])
      .map((t) => ({ ...t, effective: effectiveAuthorization(t) }))
      .filter((t) => status === 'all' || t.effective === status)
      .filter((t) => !q || [t.name, t.organization, t.baseDomain].some((s) => s.toLowerCase().includes(q)));
  }, [data, query, status]);

  const columns = [
    { key: 'name', header: 'Target', render: (t) => <Link to={`/targets/${t.id}`}>{t.name}</Link> },
    { key: 'organization', header: 'Organization' },
    { key: 'baseDomain', header: 'Base domain' },
    { key: 'effective', header: 'Authorization', render: (t) => <AuthorizationBadge status={t.effective} /> },
    { key: 'assessments', header: 'Assessments', render: (t) => t.assessments.length },
    { key: 'createdAt', header: 'Registered', render: (t) => formatDate(t.createdAt) },
  ];
  const registerBtn = canRegister && <Link className="btn btn--primary" to="/targets/new">Register target</Link>;

  return (
    <>
      <PageHeader title="Targets" description="Registered targets and their authorization." actions={registerBtn} />
      {loading && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <Panel>
          <div className="toolbar">
            <input className="input" type="search" placeholder="Search name, organization or domain" aria-label="Search targets"
              value={query} onChange={(e) => setQuery(e.target.value)} />
            <select className="input" aria-label="Filter by authorization" value={status} onChange={(e) => setStatus(e.target.value)}>
              {FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          {data.length === 0 ? (
            <EmptyState title="No targets visible to you" hint="Targets you register, or that are shared with you through an assessment, appear here." action={registerBtn} />
          ) : rows.length === 0 ? (
            <EmptyState title="No targets match" hint="Clear the search or change the status filter."
              action={<button className="btn" onClick={() => { setQuery(''); setStatus('all'); }}>Clear filters</button>} />
          ) : (
            <DataTable columns={columns} rows={rows} caption="Registered targets" />
          )}
        </Panel>
      )}
    </>
  );
}
