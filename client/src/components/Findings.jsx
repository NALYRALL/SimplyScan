import FindingCard from "./FindingCard";

function Findings({ pages }) {
  const findings = pages.flatMap((page) =>
    (page.findings || []).map((finding) => ({
      ...finding,
      pageUrl: page.url,
    }))
  );

  return (
    <div className="findings">
      <h2>Security Findings</h2>

      {findings.length === 0 ? (
        <p>No findings detected.</p>
      ) : (
        findings.map((finding, index) => (
          <FindingCard
            key={index}
            finding={finding}
          />
        ))
      )}
    </div>
  );
}

export default Findings;