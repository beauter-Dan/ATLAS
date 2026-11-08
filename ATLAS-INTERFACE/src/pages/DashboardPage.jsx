import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import StatCard from '../components/StatCard.jsx';
import Badge from '../components/Badge.jsx';
import { Loading, ErrorState, EmptyState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { getDashboardSummary } from '../services/dashboardService.js';
import { timeAgo } from '../utils/format.js';

export default function DashboardPage() {
  const { data, loading, error, reload } = useApi(getDashboardSummary);

  return (
    <>
      <PageHeader title="Dashboard" description="Current state of registered targets and assessments."
        actions={<button className="btn" onClick={reload} disabled={loading}>{loading && data ? 'Refreshing' : 'Refresh'}</button>} />
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <>
          <div className="stat-grid">
            <StatCard label="Registered targets" value={data.targets} to="/targets" />
            <StatCard label="Active assessments" value={data.activeAssessments} to="/assessments" />
            <StatCard label="Discovered assets" value={data.assets} to="/assets" />
            <StatCard label="Technologies identified" value={data.technologies} to="/assets" />
            <StatCard label="Pending hypotheses" value={data.pendingHypotheses} to="/analysis" />
            <StatCard label="Confirmed findings" value={data.confirmedFindings} to="/findings" />
          </div>
          <div className="two-col">
            <Panel title="Assessment progress">
              {data.assessmentProgress.length === 0
                ? <EmptyState title="No assessments running" hint="Create an assessment to start collecting." />
                : data.assessmentProgress.map((a) => (
                  <div className="progress-row" key={a.id}>
                    <div className="progress-row__head">
                      <span>{a.name} <span className="muted">{a.percent}%</span></span>
                      <Badge tone="info">{a.status}</Badge>
                    </div>
                    <div className="bar" role="progressbar" aria-label={a.name} aria-valuenow={a.percent} aria-valuemin="0" aria-valuemax="100">
                      <div className="bar__fill" style={{ width: `${a.percent}%` }} />
                    </div>
                  </div>
                ))}
            </Panel>
            <Panel title="Recent activity">
              {data.recentActivity.length === 0
                ? <EmptyState title="No activity yet" hint="Activity appears here once a target is registered and an assessment runs." />
                : <ul className="feed">{data.recentActivity.map((e) => (
                    <li key={e.id}><span>{e.message}</span><span className="muted">{timeAgo(e.timestamp)}</span></li>
                  ))}</ul>}
            </Panel>
          </div>
        </>
      )}
    </>
  );
}
