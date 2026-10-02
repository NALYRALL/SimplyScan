import FindingCard from "./FindingCard";

function Findings({ pages }) {
  const findings = pages.flatMap((page) =>
    (page.findings || []).map((finding) => ({
      ...finding,
      pageUrl: page.url,
    }))
  );

  const groupedFindings = {
    high: findings.filter((finding) => finding.severity === "high"),
    medium: findings.filter((finding) => finding.severity === "medium"),
    low: findings.filter((finding) => finding.severity === "low"),
    info: findings.filter((finding) => finding.severity === "info"),
  };

  return (
    <div className="findings">
      <h2>Security Findings</h2>

      {findings.length === 0 && (
        <p>No findings detected.</p>
      )}

      {Object.entries(groupedFindings).map(
        ([severity, severityFindings]) =>
          severityFindings.length > 0 && (
            <div className="finding-section" key={severity}>
              <h3 className={`section-title ${severity}`}>
                {severity.toUpperCase()} ({severityFindings.length})
              </h3>

              {severityFindings.map((finding, index) => (
                <FindingCard
                  key={index}
                  finding={finding}
                />
              ))}
            </div>
          )
      )}
    </div>
  );
}

export default Findings;