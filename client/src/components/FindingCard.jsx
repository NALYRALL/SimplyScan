function FindingCard({ finding = {} }) {
  const severity = String(
    finding.severity || "info"
  ).toLowerCase();

  return (
    <article className="finding-card">
      <div className="finding-content">
        <div className="finding-title-row">
          <strong>
            {finding.title ||
              finding.type ||
              "Security Finding"}
          </strong>

          <span className={`severity ${severity}`}>
            {severity}
          </span>
        </div>

        <p>
          {finding.description ||
            finding.message ||
            finding.detail ||
            "No additional details available."}
        </p>

        <div className="finding-meta">
          {finding.type && (
            <small>Type: {finding.type}</small>
          )}

          {finding.status_code && (
            <small>
              Status: {finding.status_code}
            </small>
          )}

          {finding.url && (
            <small className="break-text">
              URL: {finding.url}
            </small>
          )}

          {finding.pageUrl && (
            <small className="break-text">
              Page: {finding.pageUrl}
            </small>
          )}
        </div>
      </div>
    </article>
  );
}

export default FindingCard;
