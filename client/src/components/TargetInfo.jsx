function TargetInfo({ result = {} }) {
  const summary = result.summary || {};

  return (
    <section className="section target-info">
      <div className="section-heading">
        <h2>Target Information</h2>
        <span>Scan target</span>
      </div>

      <div className="target-grid">
        <div>
          <span>Target</span>
          <strong className="break-text">
            {result.target || "Unknown"}
          </strong>
        </div>

        <div>
          <span>Pages Scanned</span>
          <strong>{summary.pages_scanned || 0}</strong>
        </div>

        <div>
          <span>Scan Status</span>
          <strong className="status-completed">
            Completed
          </strong>
        </div>
      </div>
    </section>
  );
}

export default TargetInfo;
