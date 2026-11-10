import { Link, useParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import Badge from '../components/Badge.jsx';
import AuthorizationBadge from '../components/AuthorizationBadge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { getTarget } from '../services/targetService.js';
import { effectiveAuthorization } from '../utils/scope.js';
import { hasRole } from '../utils/roles.js';
import { formatDate } from '../utils/format.js';

const NOTICE = {
  pending: 'This target is not authorized yet. Assessments cannot be activated until a valid authorization record exists.',
  expired: 'The authorization window has ended. Do not assess this target until authorization is renewed.',
  revoked: 'Authorization was revoked. Do not assess this target.',
};

const AssetList = ({ items, empty }) => (items.length === 0
  ? <p className="muted">{empty}</p>
  : <ul className="asset-list">{items.map((a) => <li key={a}>{a}</li>)}</ul>);

export default function TargetDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data: t, loading, error, reload } = useApi(() => getTarget(id), [id]);

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} onRetry={reload} />;

  const effective = effectiveAuthorization(t);
  const a = t.authorization;
  const withScope = t.assessments.filter((x) => t.scope[x.id]);

  return (
    <>
      <PageHeader title={t.name} description={`${t.organization}${t.description ? ` · ${t.description}` : ''}`}
        actions={<><Link className="btn" to="/targets">All targets</Link>
          {hasRole(user, 'analyst') && <Link className="btn" to={`/assessments/new?target=${t.id}`}>New assessment</Link>}
          {hasRole(user, 'analyst') && <Link className="btn btn--primary" to={`/targets/${t.id}/edit`}>Edit target</Link>}</>} />

      {effective !== 'authorized' && <div className="notice notice--warn" role="status">{NOTICE[effective]}</div>}

      <div className="two-col">
        <Panel title="Authorization">
          <dl className="kv">
            <dt>Status</dt><dd><AuthorizationBadge status={effective} /></dd>
            <dt>Base domain</dt><dd>{t.baseDomain}</dd>
            <dt>Reference</dt><dd>{a.reference || 'Not set'}</dd>
            <dt>Granted by</dt><dd>{a.authorizedBy || 'Not set'}</dd>
            <dt>Valid from</dt><dd>{formatDate(a.validFrom)}</dd>
            <dt>Valid until</dt><dd>{formatDate(a.validUntil)}</dd>
          </dl>
        </Panel>
        <Panel title="Scope">
          {withScope.length === 0 ? (
            <p className="muted">No scope is defined yet. Permitted and excluded assets are set per assessment by an approver.</p>
          ) : withScope.map((x) => (
            <div className="scope-block" key={x.id}>
              <h3 className="subhead">{x.name}</h3>
              <div className="badge-row"><Badge tone="ok">{t.scope[x.id].permitted.length} permitted</Badge><Badge tone="danger">{t.scope[x.id].excluded.length} excluded</Badge></div>
              <h4 className="subhead">Permitted</h4><AssetList items={t.scope[x.id].permitted} empty="None." />
              <h4 className="subhead">Excluded</h4><AssetList items={t.scope[x.id].excluded} empty="No exclusions." />
            </div>
          ))}
          <p className="muted field__hint">Excluded assets are never assessed, even if they also match a permitted pattern.</p>
        </Panel>
      </div>

      <Panel title="Assessment history" className="gap-top">
        {t.assessments.length === 0
          ? <EmptyState title="No assessments yet" hint="Assessments for this target will be listed here." />
          : <DataTable caption="Assessment history" rows={t.assessments} columns={[
              { key: 'name', header: 'Assessment', render: (r) => <Link to={`/assessments/${r.id}`}>{r.name}</Link> },
              { key: 'status', header: 'Status', render: (r) => <Badge tone="info">{r.status}</Badge> },
              { key: 'startedAt', header: 'Created', render: (r) => formatDate(r.startedAt) },
            ]} />}
      </Panel>
    </>
  );
}
