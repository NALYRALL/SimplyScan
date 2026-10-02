function TargetInfo({ result }) {
  return (
    <div className="target-info">
      <h2>Target Information</h2>

      <div className="target-grid">
        <div>
          <span>Target</span>
          <strong>{result.target}</strong>
        </div>

        <div>
          <span>Pages Scanned</span>
          <strong>{result.summary.pages_scanned}</strong>
        </div>

        <div>
          <span>Scan Status</span>
          <strong>Completed</strong>
        </div>
      </div>
    </div>
  );
}

export default TargetInfo;