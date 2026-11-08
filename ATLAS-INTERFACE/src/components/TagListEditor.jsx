import { useState } from 'react';
import { normalizeAsset } from '../utils/scope.js';

export default function TagListEditor({ id, values, onChange, placeholder, label, ...aria }) {
  const [draft, setDraft] = useState('');

  const add = () => {
    const v = normalizeAsset(draft);
    if (!v) return;
    if (!values.map(normalizeAsset).includes(v)) onChange([...values, v]);
    setDraft('');
  };

  return (
    <div>
      <div className="tag-input">
        <input id={id} className="input" value={draft} placeholder={placeholder} {...aria}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); add(); } }} />
        <button type="button" className="btn" onClick={add}>Add</button>
      </div>
      {values.length > 0 && (
        <ul className="tags">
          {values.map((v) => (
            <li key={v} className="tag">
              <span>{v}</span>
              <button type="button" aria-label={`Remove ${v} from ${label}`} onClick={() => onChange(values.filter((x) => x !== v))}>×</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
