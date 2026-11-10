import { Fragment, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import DataTable from '../components/DataTable.jsx';
import Badge from '../components/Badge.jsx';
import Field from '../components/Field.jsx';
import { Loading, ErrorState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { addMember, addRule, getAssessment, removeMember, removeRule, setStatus } from '../services/assessmentService.js';
import { STATUS_TRANSITIONS } from '../services/mappers.js';
import { MATCH_TYPES, validateRuleValue } from '../utils/scope.js';
import { describeActionError } from '../utils/errors.js';
import { hasRole } from '../utils/roles.js';
import { formatDate } from '../utils/format.js';
import { STATUS_TONE } from './AssessmentsPage.jsx';

const ACTION = { active: 'Activate', paused: 'Pause', completed: 'Complete', archived: 'Archive' };
const label = (from, to) => (from === 'paused' && to === 'active' ? 'Resume' : ACTION[to]);
const COUNT_LABELS = [['assets', 'Assets'], ['observations', 'Observations'], ['hypotheses', 'Hypotheses'], ['experiments', 'Experiments'], ['findings', 'Findings']];

export default function AssessmentDetailPage() {
  const { id } = useParams();
  const { user } = useAuth();
  const { data: a, loading, error, reload } = useApi(() => getAssessment(id), [id]);
  const [actionError, setActionError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [rule, setRule] = useState({ type: 'include', match: 'domain', value: '', note: '' });
  const [ruleError, setRuleError] = useState('');
  const [member, setMember] = useState({ username: '', permission: 'viewer' });

  // Server-side permission checks are authoritative; these only decide what to show.
  const canScope = hasRole(user, 'approver');
  const canMembers = hasRole(user, 'analyst');

  async function run(fn) {
    setBusy(true); setActionError(null);
    try { await fn(); await reload(); return true; }
    catch (err) { setActionError(err); return false; }
    finally { setBusy(false); }
  }

  async function submitRule(e) {
    e.preventDefault();
    const msg = validateRuleValue(rule.match, rule.value);
    setRuleError(msg);
    if (msg) return;
    if (await run(() => addRule(id, rule))) setRule((r) => ({ ...r, value: '', note: '' }));
  }
  async function submitMember(e) {
    e.preventDefault();
    if (await run(() => addMember(id, member.username, member.permission))) setMember((m) => ({ ...m, username: '' }));
  }

  if (loading) return <Loading />;
  if (error) return <ErrorState error={error} onRetry={reload} />;

  const next = STATUS_TRANSITIONS[a.status] || [];
  const hint = MATCH_TYPES.find(([k]) => k === rule.match)?.[2];

  return (
    <>
      <PageHeader title={a.name} description={`${a.environment}${a.description ? ` · ${a.description}` : ''}`}
        actions={<><Link className="btn" to="/assessments">All assessments</Link>
          {canScope && next.map((to) => <button key={to} className={`btn ${to === 'active' ? 'btn--primary' : ''}`} disabled={busy} onClick={() => run(() => setStatus(id, to))}>{label(a.status, to)}</button>)}</>} />

      {a.status === 'draft' && <div className="notice notice--warn" role="status">This assessment is a draft. Collection and experiments cannot run until an approver activates it.</div>}
      {a.status === 'paused' && <div className="notice notice--warn" role="status">This assessment is paused. Nothing can be collected or run until it is resumed.</div>}
      {a.target && a.target.authorizationStatus !== 'authorized' && <div className="notice notice--warn" role="status">The target’s authorization is {a.target.authorizationStatus}. This assessment cannot be activated or run.</div>}
      {actionError && <div className="notice notice--warn" role="alert">{describeActionError(actionError)}</div>}

      <div className="two-col">
        <Panel title="Summary">
          <dl className="kv">
            <dt>Status</dt><dd><Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge></dd>
            <dt>Target</dt><dd>{a.target ? <Link to={`/targets/${a.target.id}`}>{a.target.name}</Link> : 'Unknown'}</dd>
            <dt>Environment</dt><dd>{a.environment}</dd>
            <dt>Created</dt><dd>{formatDate(a.createdAt)}</dd>
          </dl>
        </Panel>
        <Panel title="Collected so far">
          <dl className="kv">{COUNT_LABELS.map(([k, l]) => <Fragment key={k}><dt>{l}</dt><dd>{a.counts[k] ?? 0}</dd></Fragment>)}</dl>
        </Panel>
      </div>

      <Panel title="Scope rules" className="gap-top">
        <p className="muted field__hint">Excluded rules always win. Anything not matched by a permitted rule is not authorized, even if it was discovered.</p>
        {a.rules.length === 0 ? <p className="muted">No rules yet. Add at least one permitted rule before activating.</p> : (
          <DataTable caption="Scope rules" rows={a.rules} columns={[
            { key: 'type', header: 'Rule', render: (r) => <Badge tone={r.type === 'include' ? 'ok' : 'danger'}>{r.type === 'include' ? 'Permitted' : 'Excluded'}</Badge> },
            { key: 'match', header: 'Match', render: (r) => MATCH_TYPES.find(([k]) => k === r.match)?.[1] || r.match },
            { key: 'value', header: 'Value' },
            { key: 'note', header: 'Note' },
            { key: 'actions', header: '', render: (r) => canScope && <button className="btn" disabled={busy} aria-label={`Remove rule ${r.value}`} onClick={() => run(() => removeRule(r.id))}>Remove</button> },
          ]} />
        )}
        {canScope ? (
          <form onSubmit={submitRule} noValidate className="inline-form">
            <Field label="Rule">{(p) => <select className="input" value={rule.type} onChange={(e) => setRule({ ...rule, type: e.target.value })} {...p}><option value="include">Permitted</option><option value="exclude">Excluded</option></select>}</Field>
            <Field label="Match">{(p) => <select className="input" value={rule.match} onChange={(e) => { setRule({ ...rule, match: e.target.value }); setRuleError(''); }} {...p}>{MATCH_TYPES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select>}</Field>
            <Field label="Value" hint={hint} error={ruleError}>{(p) => <input className="input" value={rule.value} onChange={(e) => setRule({ ...rule, value: e.target.value })} {...p} />}</Field>
            <Field label="Note">{(p) => <input className="input" value={rule.note} onChange={(e) => setRule({ ...rule, note: e.target.value })} {...p} />}</Field>
            <button className="btn btn--primary" type="submit" disabled={busy}>Add rule</button>
          </form>
        ) : <p className="muted field__hint">Only approvers can change scope.</p>}
      </Panel>

      <Panel title="Members" className="gap-top">
        <DataTable caption="Members" rows={a.members} rowKey="userId" columns={[
          { key: 'username', header: 'User', render: (m) => <>{m.username}{m.isOwner && <> <Badge tone="info">owner</Badge></>}</> },
          { key: 'permission', header: 'Permission on this assessment' },
          { key: 'actions', header: '', render: (m) => canMembers && !m.isOwner && <button className="btn" disabled={busy} aria-label={`Remove ${m.username}`} onClick={() => run(() => removeMember(id, m.userId))}>Remove</button> },
        ]} />
        {canMembers && (
          <form onSubmit={submitMember} noValidate className="inline-form">
            <Field label="Username">{(p) => <input className="input" value={member.username} onChange={(e) => setMember({ ...member, username: e.target.value })} {...p} />}</Field>
            <Field label="Permission" hint="Capped by the person’s global role.">{(p) => <select className="input" value={member.permission} onChange={(e) => setMember({ ...member, permission: e.target.value })} {...p}>{['viewer', 'analyst', 'approver'].map((x) => <option key={x}>{x}</option>)}</select>}</Field>
            <button className="btn btn--primary" type="submit" disabled={busy || !member.username.trim()}>Add or update</button>
          </form>
        )}
      </Panel>
    </>
  );
}
