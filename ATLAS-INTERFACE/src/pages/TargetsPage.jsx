import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import AuthorizationBadge from '../components/AuthorizationBadge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { listTargets } from '../services/targetService.js';
import { effectiveAuthorization } from '../utils/scope.js';
import { formatDate } from '../utils/format.js';

const FILTERS = [
  ['all', 'All statuses'], ['authorized', 'Authorized'], ['pending', 'Pending'], ['expired', 'Expired'], ['revoked', 'Revoked'],
];

export default function TargetsPage() {
  const { data, loading, error, reload } = useApi(listTargets);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data || [])
      .map((t) => ({ ...t, effective: effectiveAuthorization(t) }))
      .filter((t) => status === 'all' || t.effective === status)
      .filter((t) => !q || [t.name, t.organization, ...t.permittedAssets].some((s) => s.toLowerCase().includes(q)));
  }, [data, query, status]);

  const columns = [
    { key: 'name', header: 'Target', render: (t) => <Link to={`/targets/${t.id}`}>{t.name}</Link> },
    { key: 'organization', header: 'Organization' },
    { key: 'effective', header: 'Authorization', render: (t) => <AuthorizationBadge status={t.effective} /> },
    { key: 'permitted', header: 'Permitted', render: (t) => t.permittedAssets.length },
    { key: 'excluded', header: 'Excluded', render: (t) => t.excludedAssets.length },
    { key: 'updatedAt', header: 'Updated', render: (t) => formatDate(t.updatedAt) },
  ];

  return (
    <>
      <PageHeader title="Targets" description="Registered targets and their authorization."
        actions={<Link className="btn btn--primary" to="/targets/new">Register target</Link>} />
      {loading && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <Panel>
          <div className="toolbar">
            <input className="input" type="search" placeholder="Search name, organization or asset" aria-label="Search targets"
              value={query} onChange={(e) => setQuery(e.target.value)} />
            <select className="input" aria-label="Filter by authorization" value={status} onChange={(e) => setStatus(e.target.value)}>
              {FILTERS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
          {data.length === 0 ? (
            <EmptyState title="No targets registered" hint="Register a target to define its authorization and scope."
              action={<Link className="btn btn--primary" to="/targets/new">Register target</Link>} />
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
