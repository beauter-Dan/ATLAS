import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import Field from '../components/Field.jsx';
import { Loading, ErrorState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { listTargets } from '../services/targetService.js';
import { createAssessment } from '../services/assessmentService.js';
import { describeActionError } from '../utils/errors.js';

export default function AssessmentFormPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const targets = useApi(listTargets);
  const [form, setForm] = useState({ targetId: params.get('target') || '', name: '', environment: 'staging', description: '' });
  const [errors, setErrors] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    const errs = {};
    if (!form.targetId) errs.targetId = 'Choose a target.';
    if (!form.name.trim()) errs.name = 'Enter a name.';
    else if (form.name.trim().length > 200) errs.name = 'Use 200 characters or fewer.';
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setSaving(true); setSaveError(null);
    try { navigate(`/assessments/${(await createAssessment(form)).id}`); }
    catch (err) { setSaveError(err); setSaving(false); }
  }

  if (targets.loading) return <Loading />;
  if (targets.error) return <ErrorState error={targets.error} onRetry={targets.reload} />;

  return (
    <>
      <PageHeader title="New assessment" description="You become the owner. An approver defines the scope and activates it." />
      <form onSubmit={submit} noValidate>
        <Panel title="Assessment">
          <Field label="Target" error={errors.targetId}>
            {(p) => (
              <select className="input" value={form.targetId} onChange={set('targetId')} {...p}>
                <option value="">Select a target</option>
                {targets.data.map((t) => <option key={t.id} value={t.id}>{t.name} ({t.baseDomain})</option>)}
              </select>
            )}
          </Field>
          <Field label="Name" error={errors.name}>{(p) => <input className="input" value={form.name} onChange={set('name')} {...p} />}</Field>
          <Field label="Environment" hint="Experiments on production are capped at 3 requests and 6 per minute.">
            {(p) => <select className="input" value={form.environment} onChange={set('environment')} {...p}>{['test', 'staging', 'production'].map((x) => <option key={x}>{x}</option>)}</select>}
          </Field>
          <Field label="Description">{(p) => <textarea className="input" rows="3" value={form.description} onChange={set('description')} {...p} />}</Field>
        </Panel>
        {saveError && <div className="notice notice--warn" role="alert">{describeActionError(saveError)}</div>}
        <div className="form-actions">
          <Link className="btn" to="/assessments">Cancel</Link>
          <button className="btn btn--primary" type="submit" disabled={saving}>{saving ? 'Creating' : 'Create assessment'}</button>
        </div>
      </form>
    </>
  );
}
