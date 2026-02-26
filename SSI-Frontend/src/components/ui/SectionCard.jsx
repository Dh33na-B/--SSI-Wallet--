export default function SectionCard({ title, subtitle, right, children }) {
  return (
    <section className="section-card">
      <div className="section-card__header">
        <div>
          <h3>{title}</h3>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {right ? <div>{right}</div> : null}
      </div>
      <div className="section-card__body">{children}</div>
    </section>
  );
}
