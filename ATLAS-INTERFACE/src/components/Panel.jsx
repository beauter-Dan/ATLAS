export default function Panel({ title, children, className = '' }) {
  return (
    <section className={`panel ${className}`}>
      {title && <h2 className="panel__title">{title}</h2>}
      {children}
    </section>
  );
}
