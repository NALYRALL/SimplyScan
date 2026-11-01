function ConnectionInfo({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const httpsCount = safePages.filter((page) =>
    String(page.url || "").startsWith("https://")
  ).length;

  const httpCount = safePages.filter((page) =>
    String(page.url || "").startsWith("http://")
  ).length;

  const redirectCount = safePages.reduce(
    (total, page) =>
      total +
      (Array.isArray(page.redirects)
        ? page.redirects.length
        : 0),
    0
  );

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Connection & Redirects</h2>
        <span>Transport and navigation</span>
      </div>

      <div className="connection-grid">
        <div className="connection-card">
          <span>HTTPS Pages</span>
          <strong>{httpsCount}</strong>
        </div>

        <div className="connection-card">
          <span>HTTP Pages</span>
          <strong>{httpCount}</strong>
        </div>

        <div className="connection-card">
          <span>Redirects</span>
          <strong>{redirectCount}</strong>
        </div>
      </div>
    </section>
  );
}

export default ConnectionInfo;
