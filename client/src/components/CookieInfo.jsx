function CookieInfo({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const cookies = safePages.flatMap((page) => {
    if (Array.isArray(page.cookies)) {
      return page.cookies.map((cookie) => ({
        ...cookie,
        pageUrl: page.url,
      }));
    }

    if (Array.isArray(page.cookie_analysis)) {
      return page.cookie_analysis.map((cookie) => ({
        ...cookie,
        pageUrl: page.url,
      }));
    }

    return [];
  });

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Cookie Security</h2>
        <span>Cookie protection attributes</span>
      </div>

      {cookies.length === 0 ? (
        <p className="muted">No cookies detected.</p>
      ) : (
        <div className="cookie-list">
          {cookies.map((cookie, index) => {
            const secure = Boolean(cookie.secure);
            const httpOnly = Boolean(
              cookie.httponly ?? cookie.httpOnly
            );

            const sameSite =
              cookie.samesite ??
              cookie.sameSite ??
              "Not set";

            return (
              <div className="cookie-card" key={index}>
                <div className="cookie-header">
                  <strong>
                    {cookie.name || "Unknown Cookie"}
                  </strong>

                  <span className="break-text">
                    {cookie.pageUrl}
                  </span>
                </div>

                <div className="cookie-properties">
                  <div>
                    <span>Secure</span>
                    <strong>{secure ? "Yes" : "No"}</strong>
                  </div>

                  <div>
                    <span>HttpOnly</span>
                    <strong>
                      {httpOnly ? "Yes" : "No"}
                    </strong>
                  </div>

                  <div>
                    <span>SameSite</span>
                    <strong>{sameSite}</strong>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}

export default CookieInfo;
