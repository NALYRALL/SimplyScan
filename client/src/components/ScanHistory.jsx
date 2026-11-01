function ScanHistory({
  history = [],
  onSelect,
}) {
  const safeHistory = Array.isArray(history)
    ? history
    : [];

  return (
    <section className="scan-history">
      <div className="section-heading">
        <h2>Scan History</h2>
        <span>Last 5 scans</span>
      </div>

      {safeHistory.length === 0 ? (
        <div className="empty-history">
          <span>No previous scans yet.</span>
        </div>
      ) : (
        <div className="history-list">
          {safeHistory.map((scan, index) => (
            <button
              type="button"
              className="history-card"
              key={scan.id || `${scan.target}-${index}`}
              onClick={() =>
                onSelect?.(scan)
              }
            >
              <div>
                <strong className="break-text">
                  {scan.target || "Unknown target"}
                </strong>

                <span>
                  {scan.timestamp
                    ? new Date(
                        scan.timestamp
                      ).toLocaleString()
                    : "Previous scan"}
                </span>
              </div>

              <div className="history-summary">
                <span className="history-high">
                  H {scan.summary?.high || 0}
                </span>
                <span className="history-medium">
                  M {scan.summary?.medium || 0}
                </span>
                <span className="history-low">
                  L {scan.summary?.low || 0}
                </span>
              </div>
            </button>
          ))}
        </div>
      )}
    </section>
  );
}

export default ScanHistory;
