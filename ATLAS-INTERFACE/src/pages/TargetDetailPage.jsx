import { Link, useParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import Badge from '../components/Badge.jsx';
import AuthorizationBadge from '../components/AuthorizationBadge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { getTarget } from '../services/targetService.js';
import { effectiveAuthorization } from '../utils/scope.js';
import { formatDate } from '../utils/format.js';

const NOTICE = {
  pending: 'This target is not authorized yet. Assessments should not be started until authorization is confirmed.',
  expired: 'The authorization window has ended. Do not assess this target until authorization is renewed.',
  revoked: 'Authorization was revoked. Do not assess this target.',
};

function AssetList({ items, empty }) {
  return items.length === 0
    ? <p className="muted">{empty}</p>
    : <ul className="asset-list">{items.map((a) => <li key={a}>{a}</li>)}</ul>;
}

export default function TargetDetailPage() {
  const { id } = useParams();
  const { data: t, loading, error, reload } = useApi(() => getTarget(id), [id]);

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} onRetry={reload} />;

  const effective = effectiveAuthorization(t);
  const a = t.authorization;

  return (
    <>
      <PageHeader title={t.name} description={`${t.organization}${t.description ? ` · ${t.description}` : ''}`}
        actions={<><Link className="btn" to="/targets">All targets</Link><Link className="btn btn--primary" to={`/targets/${t.id}/edit`}>Edit target</Link></>} />

      {effective !== 'authorized' && <div className="notice notice--warn" role="status">{NOTICE[effective]}</div>}

      <div className="two-col">
        <Panel title="Authorization">
          <dl className="kv">
            <dt>Status</dt><dd><AuthorizationBadge status={effective} /></dd>
            <dt>Reference</dt><dd>{a.reference}</dd>
            <dt>Granted by</dt><dd>{a.authorizedBy}</dd>
            <dt>Valid from</dt><dd>{formatDate(a.validFrom)}</dd>
            <dt>Valid until</dt><dd>{formatDate(a.validUntil)}</dd>
          </dl>
        </Panel>
        <Panel title="Scope">
          <h3 className="subhead">Permitted assets <Badge tone="ok">{t.permittedAssets.length}</Badge></h3>
          <AssetList items={t.permittedAssets} empty="No permitted assets defined." />
          <h3 className="subhead">Excluded assets <Badge tone="danger">{t.excludedAssets.length}</Badge></h3>
          <AssetList items={t.excludedAssets} empty="No exclusions defined." />
          <p className="muted field__hint">Excluded assets are never assessed, even if they also match a permitted pattern.</p>
        </Panel>
      </div>

      <Panel title="Assessment history" className="gap-top">
        {t.assessments.length === 0
          ? <EmptyState title="No assessments yet" hint="Assessments for this target will be listed here." />
          : <DataTable caption="Assessment history" rows={t.assessments} columns={[
              { key: 'name', header: 'Assessment' },
              { key: 'status', header: 'Status', render: (r) => <Badge tone="info">{r.status}</Badge> },
              { key: 'startedAt', header: 'Started', render: (r) => formatDate(r.startedAt) },
            ]} />}
      </Panel>
    </>
  );
}
