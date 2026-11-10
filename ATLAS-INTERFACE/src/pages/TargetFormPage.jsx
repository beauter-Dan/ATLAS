import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import Field from '../components/Field.jsx';
import { Loading, ErrorState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { createTarget, getTarget, updateTarget } from '../services/targetService.js';
import { validateTarget } from '../utils/scope.js';
import { hasRole } from '../utils/roles.js';
import { describeActionError } from '../utils/errors.js';

const BLANK = {
  name: '', organization: '', baseDomain: '', description: '',
  authorization: { reference: '', authorizedBy: '', validFrom: '', validUntil: '' },
};

export default function TargetFormPage() {
  const { id } = useParams();
  const editing = Boolean(id);
  const navigate = useNavigate();
  const { user } = useAuth();
  const loaded = useApi(() => (editing ? getTarget(id) : Promise.resolve(null)), [id]);

  const [form, setForm] = useState(BLANK);
  const [errors, setErrors] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  // Registering sets an authorization record; changing one later needs an approver (the server enforces this too).
  const canEditAuth = !editing || hasRole(user, 'approver');

  useEffect(() => {
    const t = loaded.data;
    if (t) setForm({ name: t.name, organization: t.organization, baseDomain: t.baseDomain, description: t.description, authorization: { ...t.authorization } });
  }, [loaded.data]);

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));
  const setAuth = (key) => (e) => setForm((f) => ({ ...f, authorization: { ...f.authorization, [key]: e.target.value } }));

  async function submit(e) {
    e.preventDefault();
    const errs = validateTarget(form);
    setErrors(errs);
    if (Object.keys(errs).length) return;
    setSaving(true); setSaveError(null);
    try {
      const saved = editing ? await updateTarget(id, loaded.data, form) : await createTarget(form);
      navigate(`/targets/${saved.id}`);
    } catch (err) {
      setSaveError(err); setSaving(false);
    }
  }

  if (editing && loaded.loading) return <Loading />;
  if (editing && loaded.error) return <ErrorState error={loaded.error} onRetry={loaded.reload} />;

  const auth = (key, label, type = 'text') => (
    <Field label={label} error={errors[key]}>
      {(p) => <input className="input" type={type} disabled={!canEditAuth} value={form.authorization[key]} onChange={setAuth(key)} {...p} />}
    </Field>
  );

  return (
    <>
      <PageHeader title={editing ? 'Edit target' : 'Register target'}
        description="Authorization is validated by the platform. Permitted and excluded assets are defined per assessment by an approver." />
      <form onSubmit={submit} noValidate>
        <div className="two-col">
          <Panel title="Target">
            <Field label="Name" error={errors.name}>{(p) => <input className="input" value={form.name} onChange={set('name')} {...p} />}</Field>
            <Field label="Organization" error={errors.organization}>{(p) => <input className="input" value={form.organization} onChange={set('organization')} {...p} />}</Field>
            <Field label="Base domain" hint="For example example.test. Scope rules are defined separately." error={errors.baseDomain}>{(p) => <input className="input" value={form.baseDomain} onChange={set('baseDomain')} {...p} />}</Field>
            <Field label="Description">{(p) => <textarea className="input" rows="3" value={form.description} onChange={set('description')} {...p} />}</Field>
          </Panel>
          <Panel title="Authorization">
            {!canEditAuth && <p className="muted field__hint">Only an approver or administrator can change authorization details.</p>}
            {auth('reference', 'Authorization reference')}
            {auth('authorizedBy', 'Granted by')}
            <div className="field-row">{auth('validFrom', 'Valid from', 'date')}{auth('validUntil', 'Valid until', 'date')}</div>
          </Panel>
        </div>
        {saveError && <div className="notice notice--warn" role="alert">{describeActionError(saveError)}</div>}
        <div className="form-actions">
          <Link className="btn" to={editing ? `/targets/${id}` : '/targets'}>Cancel</Link>
          <button className="btn btn--primary" type="submit" disabled={saving}>{saving ? 'Saving' : editing ? 'Save changes' : 'Register target'}</button>
        </div>
      </form>
    </>
  );
}
