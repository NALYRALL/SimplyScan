function Summary({ summary = {} }) {
  const cards = [
    ["Pages", summary.pages_scanned || 0],
    ["Info", summary.info || 0],
    ["Low", summary.low || 0],
    ["Medium", summary.medium || 0],
    ["High", summary.high || 0],
    ["Errors", summary.errors || 0],
  ];

  return (
    <section className="section summary">
      <div className="section-heading">
        <h2>Scan Summary</h2>
        <span>Finding distribution</span>
      </div>

      <div className="summary-grid">
        {cards.map(([label, value]) => (
          <div className="summary-card" key={label}>
            <span>{label}</span>
            <strong>{value}</strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export default Summary;
