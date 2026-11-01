function Redirects({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const redirects = safePages.flatMap((page) => {
    if (!Array.isArray(page.redirects)) return [];

    return page.redirects.map((redirect) => ({
      pageUrl: page.url,
      redirect,
    }));
  });

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Redirects</h2>
        <span>Observed redirect chains</span>
      </div>

      {redirects.length === 0 ? (
        <p className="muted">No redirects recorded.</p>
      ) : (
        <div className="redirect-list">
          {redirects.map((item, index) => (
            <div className="redirect-card" key={index}>
              <span className="break-text">
                {item.pageUrl}
              </span>

              <pre>
                {typeof item.redirect === "string"
                  ? item.redirect
                  : JSON.stringify(
                      item.redirect,
                      null,
                      2
                    )}
              </pre>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default Redirects;
