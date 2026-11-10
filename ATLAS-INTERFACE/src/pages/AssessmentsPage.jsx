import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import Badge from '../components/Badge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { listAssessments } from '../services/assessmentService.js';
import { hasRole } from '../utils/roles.js';
import { formatDate } from '../utils/format.js';

export const STATUS_TONE = { draft: 'neutral', active: 'ok', paused: 'warn', completed: 'info', archived: 'neutral' };
const STATUSES = ['all', 'draft', 'active', 'paused', 'completed', 'archived'];

export default function AssessmentsPage() {
  const { user } = useAuth();
  const { data, loading, error, reload } = useApi(listAssessments);
  const [query, setQuery] = useState('');
  const [status, setStatus] = useState('all');
  const canCreate = hasRole(user, 'analyst');

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (data || []).filter((a) => (status === 'all' || a.status === status) && (!q || [a.name, a.targetName].some((s) => s.toLowerCase().includes(q))));
  }, [data, query, status]);

  const newBtn = canCreate && <Link className="btn btn--primary" to="/assessments/new">New assessment</Link>;
  const columns = [
    { key: 'name', header: 'Assessment', render: (a) => <Link to={`/assessments/${a.id}`}>{a.name}</Link> },
    { key: 'targetName', header: 'Target', render: (a) => <Link to={`/targets/${a.targetId}`}>{a.targetName}</Link> },
    { key: 'status', header: 'Status', render: (a) => <Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge> },
    { key: 'environment', header: 'Environment' },
    { key: 'createdAt', header: 'Created', render: (a) => formatDate(a.createdAt) },
  ];

  return (
    <>
      <PageHeader title="Assessments" description="Configure, activate and monitor assessments." actions={newBtn} />
      {loading && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <Panel>
          <div className="toolbar">
            <input className="input" type="search" placeholder="Search assessment or target" aria-label="Search assessments" value={query} onChange={(e) => setQuery(e.target.value)} />
            <select className="input" aria-label="Filter by status" value={status} onChange={(e) => setStatus(e.target.value)}>
              {STATUSES.map((s) => <option key={s} value={s}>{s === 'all' ? 'All statuses' : s}</option>)}
            </select>
          </div>
          {data.length === 0 ? <EmptyState title="No assessments visible to you" hint="Assessments you own, or that were shared with you, appear here." action={newBtn} />
            : rows.length === 0 ? <EmptyState title="No assessments match" hint="Clear the search or change the status filter." />
            : <DataTable columns={columns} rows={rows} caption="Assessments" />}
        </Panel>
      )}
    </>
  );
}
