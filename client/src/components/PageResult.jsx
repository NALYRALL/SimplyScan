import { useState } from "react";

function PageResult({ page }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="page-result">

      <div
        className="page-header"
        onClick={() => setOpen(!open)}
      >
        <strong>{page.url}</strong>

        <div>
          <span className="status-code">
            {page.status_code}
          </span>

          <span className="expand-icon">
            {open ? "−" : "+"}
          </span>
        </div>
      </div>

      {open && (
        <div className="page-details">

          <div>
            <span>Title</span>
            <strong>{page.title || "No title"}</strong>
          </div>

          <div>
            <span>Response Time</span>
            <strong>{page.response_time}s</strong>
          </div>

          <div>
            <span>Findings</span>
            <strong>{page.findings?.length || 0}</strong>
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
      )}

    </div>
  );
}

export default PageResult;