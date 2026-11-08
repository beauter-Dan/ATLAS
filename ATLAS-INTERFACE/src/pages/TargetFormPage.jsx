import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import PageHeader from '../components/PageHeader.jsx';
import Panel from '../components/Panel.jsx';
import Field from '../components/Field.jsx';
import TagListEditor from '../components/TagListEditor.jsx';
import { Loading, ErrorState } from '../components/States.jsx';
import { useApi } from '../hooks/useApi.js';
import { createTarget, getTarget, updateTarget } from '../services/targetService.js';
import { validateTarget } from '../utils/scope.js';

const BLANK = {
  name: '', organization: '', description: '',
  authorization: { reference: '', authorizedBy: '', validFrom: '', validUntil: '' },
  permittedAssets: [], excludedAssets: [],
};

export default function TargetFormPage() {
  const { id } = useParams();
  const editing = Boolean(id);
  const navigate = useNavigate();
  const loaded = useApi(() => (editing ? getTarget(id) : Promise.resolve(null)), [id]);

  const [form, setForm] = useState(BLANK);
  const [errors, setErrors] = useState({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  useEffect(() => {
    const t = loaded.data;
    if (t) setForm({
      name: t.name, organization: t.organization, description: t.description,
      authorization: { reference: t.authorization.reference, authorizedBy: t.authorization.authorizedBy, validFrom: t.authorization.validFrom, validUntil: t.authorization.validUntil },
      permittedAssets: t.permittedAssets, excludedAssets: t.excludedAssets,
    });
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
      const saved = editing ? await updateTarget(id, form) : await createTarget(form);
      navigate(`/targets/${saved.id}`);
    } catch (err) {
      setSaveError(err); setSaving(false);
    }
  }

  if (editing && loaded.loading) return <Loading />;
  if (editing && loaded.error) return <ErrorState error={loaded.error} onRetry={loaded.reload} />;

  return (
    <>
      <PageHeader title={editing ? 'Edit target' : 'Register target'}
        description="Authorization status is confirmed by the platform. Changing authorization details returns the target to pending." />
      <form onSubmit={submit} noValidate>
        <div className="two-col">
          <Panel title="Target">
            <Field label="Name" error={errors.name}>{(p) => <input className="input" value={form.name} onChange={set('name')} {...p} />}</Field>
            <Field label="Organization" error={errors.organization}>{(p) => <input className="input" value={form.organization} onChange={set('organization')} {...p} />}</Field>
            <Field label="Description">{(p) => <textarea className="input" rows="3" value={form.description} onChange={set('description')} {...p} />}</Field>
          </Panel>
          <Panel title="Authorization">
            <Field label="Authorization reference" error={errors.reference}>{(p) => <input className="input" value={form.authorization.reference} onChange={setAuth('reference')} {...p} />}</Field>
            <Field label="Granted by" error={errors.authorizedBy}>{(p) => <input className="input" value={form.authorization.authorizedBy} onChange={setAuth('authorizedBy')} {...p} />}</Field>
            <div className="field-row">
              <Field label="Valid from" error={errors.validFrom}>{(p) => <input className="input" type="date" value={form.authorization.validFrom} onChange={setAuth('validFrom')} {...p} />}</Field>
              <Field label="Valid until" error={errors.validUntil}>{(p) => <input className="input" type="date" value={form.authorization.validUntil} onChange={setAuth('validUntil')} {...p} />}</Field>
            </div>
          </Panel>
        </div>
        <Panel title="Scope" className="gap-top">
          <div className="two-col">
            <Field label="Permitted assets" hint="Press Enter to add. Wildcards like *.example.test are allowed." error={errors.permittedAssets}>
              {(p) => <TagListEditor {...p} label="permitted assets" placeholder="shop.example.test" values={form.permittedAssets} onChange={(v) => setForm((f) => ({ ...f, permittedAssets: v }))} />}
            </Field>
            <Field label="Excluded assets" hint="Never assessed, even if a permitted pattern matches." error={errors.excludedAssets}>
              {(p) => <TagListEditor {...p} label="excluded assets" placeholder="payments.example.test" values={form.excludedAssets} onChange={(v) => setForm((f) => ({ ...f, excludedAssets: v }))} />}
            </Field>
          </div>
        </Panel>
        {saveError && <ErrorState error={saveError} />}
        <div className="form-actions">
          <Link className="btn" to={editing ? `/targets/${id}` : '/targets'}>Cancel</Link>
          <button className="btn btn--primary" type="submit" disabled={saving}>{saving ? 'Saving' : editing ? 'Save changes' : 'Register target'}</button>
        </div>
      </form>
    </>
  );
}
