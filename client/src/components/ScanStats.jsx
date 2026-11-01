function ScanStats({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const responseTimes = safePages
    .map((page) => Number(page.response_time))
    .filter((value) => Number.isFinite(value));

  const average =
    responseTimes.length > 0
      ? responseTimes.reduce((a, b) => a + b, 0) /
        responseTimes.length
      : 0;

  const successful = safePages.filter(
    (page) =>
      Number(page.status_code) >= 200 &&
      Number(page.status_code) < 400
  ).length;

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Scan Statistics</h2>
        <span>Performance and result statistics</span>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <span>Total Pages</span>
          <strong>{safePages.length}</strong>
        </div>

        <div className="stat-card">
          <span>Successful Pages</span>
          <strong>{successful}</strong>
        </div>

        <div className="stat-card">
          <span>Average Response</span>
          <strong>{average.toFixed(3)}s</strong>
        </div>
      </div>
    </section>
  );
}

export default ScanStats;
