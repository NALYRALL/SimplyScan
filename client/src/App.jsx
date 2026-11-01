import { useEffect, useState } from "react";

import Summary from "./components/Summary";
import Findings from "./components/Findings";
import TargetInfo from "./components/TargetInfo";
import Pages from "./components/Pages";
import SecurityOverview from "./components/SecurityOverview";
import SecurityHeaders from "./components/SecurityHeaders";
import ConnectionInfo from "./components/ConnectionInfo";
import ServerInfo from "./components/ServerInfo";
import CookieInfo from "./components/CookieInfo";
import HtmlAnalysis from "./components/HtmlAnalysis";
import ScanStats from "./components/ScanStats";
import Redirects from "./components/Redirects";
import Footer from "./components/Footer";
import RiskScore from "./components/RiskScore";
import ScanHistory from "./components/ScanHistory";

const API_BASE_URL = (
  import.meta.env.VITE_API_URL || "http://localhost:5000"
).replace(/\/$/, "");

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [progress, setProgress] = useState("Ready to scan");
  const [history, setHistory] = useState(() => {
    try {
      const saved = localStorage.getItem("simplyscan-history");
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  useEffect(() => {
    localStorage.setItem(
      "simplyscan-history",
      JSON.stringify(history)
    );
  }, [history]);

  const handleScan = async () => {
    if (!url.trim()) {
      setError("Please enter a website URL.");
      setResult(null);
      return;
    }

    let scanUrl = url.trim();

    if (
      !scanUrl.startsWith("http://") &&
      !scanUrl.startsWith("https://")
    ) {
      scanUrl = "https://" + scanUrl;
    }

    setLoading(true);
    setError("");
    setResult(null);
    setProgress("Connecting to target...");

    try {
      setProgress("Crawling website...");

      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: scanUrl,
        }),
      });

      setProgress("Analyzing security results...");

      if (!response.ok) {
        let message = "Scan request failed.";

        try {
          const errorData = await response.json();
          message = errorData.error || message;
        } catch {
          // Keep default message.
        }

        throw new Error(message);
      }

      const data = await response.json();

      setResult(data);

      const entry = {
        id: Date.now(),
        target: data.target || scanUrl,
        summary: data.summary || {},
        timestamp: new Date().toISOString(),
      };

      setHistory((previous) => [
        entry,
        ...previous.filter(
          (item) => item.target !== entry.target
        ),
      ].slice(0, 5));

      setProgress("Scan completed");
    } catch (scanError) {
      console.error("SCAN ERROR:", scanError);
      setError(
        scanError.message || "Unable to complete the scan."
      );
      setProgress("Scan failed");
    } finally {
      setLoading(false);
    }
  };

  const handleHistorySelect = (scan) => {
    setUrl(scan.target || "");
    setError("");
  };

  return (
    <div className="app-shell">
      <header className="header">
        <div>
          <h1>SimplyScan</h1>
          <p>Passive Website Security Scanner</p>
        </div>

        <span className="scanner-badge">SAFE MODE</span>
      </header>

      <main>
        <section className="scan-panel">
          <div className="scan-form">
            <input
              type="text"
              placeholder="Enter website URL"
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !loading) {
                  handleScan();
                }
              }}
              disabled={loading}
            />

            <button
              onClick={handleScan}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan"}
            </button>
          </div>

          <div className="scan-status">
            <span
              className={
                loading
                  ? "status-dot active"
                  : error
                    ? "status-dot error"
                    : "status-dot"
              }
            />
            <span>{progress}</span>
          </div>

          {loading && (
            <div className="progress-bar">
              <div className="progress-bar-fill" />
            </div>
          )}
        </section>

        <ScanHistory
          history={history}
          onSelect={handleHistorySelect}
        />

        {error && (
          <div className="error-message">
            <strong>Scan Failed</strong>
            <p>{error}</p>
          </div>
        )}

        {result && !error && (
          <div className="success-message">
            Scan completed successfully.
          </div>
        )}

        {result && (
          <div className="results">
            <TargetInfo result={result} />

            <RiskScore summary={result.summary || {}} />

            <Summary summary={result.summary || {}} />

            <SecurityOverview pages={result.pages || []} />

            <SecurityHeaders pages={result.pages || []} />

            <ConnectionInfo pages={result.pages || []} />

            <ServerInfo pages={result.pages || []} />

            <CookieInfo pages={result.pages || []} />

            <HtmlAnalysis pages={result.pages || []} />

            <ScanStats pages={result.pages || []} />

            <Redirects pages={result.pages || []} />

            <Findings pages={result.pages || []} />

            <Pages pages={result.pages || []} />
          </div>
        )}
      </main>

      <Footer />
    </div>
  );
}

export default App;
