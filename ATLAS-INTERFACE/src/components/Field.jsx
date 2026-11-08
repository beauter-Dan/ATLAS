import { useId } from 'react';

// Wraps one control with its label and error. Pass a render function to receive the ids.
export default function Field({ label, error, hint, children }) {
  const id = useId();
  const describedBy = error ? `${id}-err` : hint ? `${id}-hint` : undefined;
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {hint && <p className="muted field__hint" id={`${id}-hint`}>{hint}</p>}
      {children({ id, 'aria-describedby': describedBy, 'aria-invalid': error ? true : undefined })}
      {error && <p className="field__error" id={`${id}-err`} role="alert">{error}</p>}
    </div>
  );
}
