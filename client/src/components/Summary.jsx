function Summary({ summary }) {
  return (
    <div className="summary">
      <h2>Scan Summary</h2>

      <div className="summary-grid">

        <div className="summary-card">
          <h3>Pages</h3>
          <p>{summary.pages_scanned}</p>
        </div>

        <div className="summary-card">
          <h3>Info</h3>
          <p>{summary.info}</p>
        </div>

        <div className="summary-card">
          <h3>Low</h3>
          <p>{summary.low}</p>
        </div>

        <div className="summary-card">
          <h3>Medium</h3>
          <p>{summary.medium}</p>
        </div>

        <div className="summary-card">
          <h3>High</h3>
          <p>{summary.high}</p>
        </div>

        <div className="summary-card">
          <h3>Errors</h3>
          <p>{summary.errors}</p>
        </div>

      </div>
    </div>
  );
}

export default Summary;