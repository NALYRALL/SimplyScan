import { useMemo, useState } from "react";
import PageResult from "./PageResult";

function Pages({ pages = [] }) {
  const [search, setSearch] = useState("");

  const safePages = Array.isArray(pages) ? pages : [];

  const filteredPages = useMemo(() => {
    const query = search.trim().toLowerCase();

    if (!query) return safePages;

    return safePages.filter((page) =>
      String(
        page.url || page.final_url || ""
      ).toLowerCase().includes(query)
    );
  }, [safePages, search]);

  return (
    <section className="section pages">
      <div className="section-heading">
        <h2>Scanned Pages</h2>
        <span>
          {filteredPages.length}/{safePages.length} shown
        </span>
      </div>

      <input
        className="page-search"
        type="text"
        placeholder="Search scanned pages..."
        value={search}
        onChange={(event) => setSearch(event.target.value)}
      />

      {filteredPages.length === 0 ? (
        <div className="empty-state">
          <strong>No matching pages.</strong>
          <span>Try a different URL or search term.</span>
        </div>
      ) : (
        <div className="page-list">
          {filteredPages.map((page, index) => (
            <PageResult
              key={`${page.url || "page"}-${index}`}
              page={page}
            />
          ))}
        </div>
      )}
    </section>
  );
}

export default Pages;
