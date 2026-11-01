function RiskScore({ summary = {} }) {
  const high = Number(summary.high || 0);
  const medium = Number(summary.medium || 0);
  const low = Number(summary.low || 0);

  const penalty = high * 20 + medium * 8 + low * 2;
  const score = Math.max(0, Math.min(100, 100 - penalty));

  let label = "Good";
  let className = "good";

  if (score < 40) {
    label = "Critical";
    className = "critical";
  } else if (score < 60) {
    label = "Needs Attention";
    className = "attention";
  } else if (score < 80) {
    label = "Fair";
    className = "fair";
  }

  return (
    <section className="risk-score">
      <div>
        <span>Security Score</span>
        <strong>{score}/100</strong>
        <small>
          Estimated score based on detected findings. Not a security certification.
        </small>
      </div>

      <div className={`risk-label ${className}`}>
        {label}
      </div>
    </section>
  );
}

export default RiskScore;
