import { useState } from "react";
import Summary from "./components/Summary";
import Findings from "./components/Findings";
import TargetInfo from "./components/TargetInfo";
import Pages from "./components/Pages";

function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!url.trim()) {
      setError("Please enter a website URL.");
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

    try {
      const response = await fetch("http://localhost:5000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: scanUrl,
        }),
      });

      if (!response.ok) {
        throw new Error("Scan request failed");
      }

      const data = await response.json();

      setResult(data);
    } catch (error) {
      console.error(error);
      setError(error.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <header className="header">
        <h1>SimplyScan</h1>
        <p>Passive Website Security Scanner</p>
      </header>

      <div className="scan-form">
        <input
          type="text"
          placeholder="Enter website URL"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />

        <button
          onClick={handleScan}
          disabled={loading}
        >
          {loading ? "Scanning..." : "Scan"}
        </button>
      </div>

      {loading && <p>Scanning website. Please wait...</p>}

      {error && <p>{error}</p>}

      {result && <TargetInfo result={result} />}

      {result && <Summary summary={result.summary} />}

      {result && <Findings pages={result.pages} />}
      
      {result && <Pages pages={result.pages} />}
    </div>
  );
}

export default App;