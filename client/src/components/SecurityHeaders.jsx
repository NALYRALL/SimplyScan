
function SecurityHeaders({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
    "Permissions-Policy",
  ];

  const headerResults = headers.map((name) => {
    const key = name.toLowerCase();

    const present = safePages.filter((page) => {
      const securityHeaders = page.security_headers || {};

      const value = Object.entries(securityHeaders).find(
        ([headerName]) => headerName.toLowerCase() === key
      )?.[1];

      return Boolean(value);
    }).length;

    return { name, present };
  });

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Security Headers</h2>
        <span>Recommended response headers</span>
      </div>

      {safePages.length === 0 ? (
        <p className="muted">No page data available.</p>
      ) : (
        <div className="headers-grid">
          {headerResults.map((header) => {
            const complete = header.present === safePages.length;

            return (
              <div className="header-card" key={header.name}>
                <div>
                  <strong>{header.name}</strong>
                  <span>
                    {header.present}/{safePages.length} pages
                  </span>
                </div>

                <span className={
                  complete
                    ? "header-status present"
                    : "header-status missing"
                }>
                  {complete ? "Present" : "Missing"}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default SecurityHeaders;
