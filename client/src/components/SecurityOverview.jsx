function SecurityOverview({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const httpsPages = safePages.filter((page) =>
    String(page.url || "").startsWith("https://")
  ).length;

  const redirects = safePages.reduce(
    (total, page) =>
      total +
      (Array.isArray(page.redirects)
        ? page.redirects.length
        : 0),
    0
  );

  const cookies = safePages.reduce((total, page) => {
    if (Array.isArray(page.cookies)) {
      return total + page.cookies.length;
    }

    if (Array.isArray(page.cookie_analysis)) {
      return total + page.cookie_analysis.length;
    }

    return total;
  }, 0);

  return (
    <section className="section security-overview">
      <div className="section-heading">
        <h2>Security Overview</h2>
        <span>Connection and site-level signals</span>
      </div>

      <div className="security-grid">
        <div className="security-card">
          <span>HTTPS Pages</span>
          <strong>
            {httpsPages}/{safePages.length}
          </strong>
        </div>

        <div className="security-card">
          <span>Redirects</span>
          <strong>{redirects}</strong>
        </div>

        <div className="security-card">
          <span>Cookies</span>
          <strong>{cookies}</strong>
        </div>
      </div>
    </section>
  );
}

export default SecurityOverview;
