import { useState } from "react";

function PageResult({ page = {} }) {
  const [open, setOpen] = useState(false);

  const status = Number(page.status_code || 0);
  const statusClass =
    status >= 200 && status < 300
      ? "success"
      : status >= 300 && status < 400
        ? "redirect"
        : status >= 400
          ? "error"
          : "unknown";

  return (
    <article className="page-result">
      <button
        type="button"
        className="page-result-header"
        onClick={() => setOpen((value) => !value)}
      >
        <div className="page-title">
          <strong className="break-text">
            {page.url || "Unknown URL"}
          </strong>

          <span className={`page-status ${statusClass}`}>
            {status || "N/A"}
          </span>
        </div>

        <span className="expand-icon">
          {open ? "−" : "+"}
        </span>
      </button>

      {open && (
        <div className="page-result-body">
          <div className="page-detail-grid">
            <div>
              <span>Final URL</span>
              <strong className="break-text">
                {page.final_url || page.url || "N/A"}
              </strong>
            </div>

            <div>
              <span>Response Time</span>
              <strong>
                {Number(page.response_time || 0).toFixed(3)}s
              </strong>
            </div>

            <div>
              <span>Content Type</span>
              <strong>
                {page.content_type || "N/A"}
              </strong>
            </div>

            <div>
              <span>Title</span>
              <strong>{page.title || "N/A"}</strong>
            </div>

            <div>
              <span>Forms</span>
              <strong>{page.forms || 0}</strong>
            </div>

            <div>
              <span>Links</span>
              <strong>{page.links || 0}</strong>
            </div>

            <div>
              <span>Scripts</span>
              <strong>{page.scripts || 0}</strong>
            </div>

            <div>
              <span>Images</span>
              <strong>{page.images || 0}</strong>
            </div>
          </div>

          {Array.isArray(page.findings) &&
            page.findings.length > 0 && (
              <div className="page-findings">
                <h4>Findings on this page</h4>

                {page.findings.map((finding, index) => (
                  <div
                    className="mini-finding"
                    key={index}
                  >
                    <span
                      className={`severity ${
                        finding.severity || "info"
                      }`}
                    >
                      {finding.severity || "info"}
                    </span>

                    <span>
                      {finding.title ||
                        finding.type ||
                        "Finding"}
                    </span>
                  </div>
                ))}
              </div>
            )}
        </div>
      )}
    </article>
  );
}

export default PageResult;
