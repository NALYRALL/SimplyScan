function ServerInfo({ pages = [] }) {
  const safePages = Array.isArray(pages) ? pages : [];

  const values = {
    Server: new Set(),
    "Content-Type": new Set(),
    "X-Powered-By": new Set(),
  };

  safePages.forEach((page) => {
    const info = page.server_info || {};

    Object.keys(values).forEach((key) => {
      const value = info[key];
      if (value) values[key].add(String(value));
    });
  });

  return (
    <section className="section">
      <div className="section-heading">
        <h2>Server Information</h2>
        <span>Response metadata observed by the scanner</span>
      </div>

      <div className="server-grid">
        {Object.entries(values).map(([key, set]) => (
          <div className="server-card" key={key}>
            <span>{key}</span>
            <strong>
              {set.size
                ? Array.from(set).join(", ")
                : "Not disclosed"}
            </strong>
          </div>
        ))}
      </div>
    </section>
  );
}

export default ServerInfo;
