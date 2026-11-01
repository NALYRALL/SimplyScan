function HtmlAnalysis({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const total = (key) =>
    safePages.reduce(
      (sum, page) => sum + Number(page[key] || 0),
      0
    );

  const items = [
    ["Forms", total("forms")],
    ["Links", total("links")],
    ["Scripts", total("scripts")],
    ["Images", total("images")],
  ];

  return (
    <section className="section">
      <div className="section-heading">
        <h2>HTML Analysis</h2>
        <span>Elements discovered across scanned pages</span>
      </div>

      <div className="html-grid">
        {items.map(([label, value]) => (
          <div className="html-card" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export default HtmlAnalysis;
