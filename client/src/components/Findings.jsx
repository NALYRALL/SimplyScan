import { useMemo, useState } from "react";
import FindingCard from "./FindingCard";

function Findings({ pages = [] }) {
  const [filter, setFilter] = useState("all");

  const safePages = Array.isArray(pages) ? pages : [];

  const findings = useMemo(() => {
    return safePages.flatMap((page) => {
      const pageFindings = Array.isArray(page.findings)
        ? page.findings
        : [];

      return pageFindings.map((finding) => ({
        ...finding,
        pageUrl: page.url,
      }));
    });
  }, [safePages]);

  const counts = {
    all: findings.length,
    high: findings.filter(
      (item) => item.severity === "high"
    ).length,
    medium: findings.filter(
      (item) => item.severity === "medium"
    ).length,
    low: findings.filter(
      (item) => item.severity === "low"
    ).length,
    info: findings.filter(
      (item) => item.severity === "info"
    ).length,
  };

  const filteredFindings =
    filter === "all"
      ? findings
      : findings.filter(
          (finding) => finding.severity === filter
        );

  return (
    <section className="section findings">
      <div className="section-heading">
        <h2>Security Findings</h2>
        <span>{findings.length} total findings</span>
      </div>

      <div className="finding-filters">
        {["all", "high", "medium", "low", "info"].map(
          (level) => (
            <button
              type="button"
              key={level}
              className={filter === level ? "active" : ""}
              onClick={() => setFilter(level)}
            >
              {level.toUpperCase()} ({counts[level]})
            </button>
          )
        )}
      </div>

      {filteredFindings.length === 0 ? (
        <div className="empty-state">
          <strong>No findings in this category.</strong>
          <span>
            Try another severity filter or run a different scan.
          </span>
        </div>
      ) : (
        <div className="finding-list">
          {filteredFindings.map((finding, index) => (
            <FindingCard
              key={`${finding.type || "finding"}-${index}`}
              finding={finding}
            />
          ))}
        </div>
      )}
    </section>
  );
}

export default Findings;
