import React from 'react';

function OverallVerdictBanner({ finding }) {
  // Backend risk score is already normalised to 0-100 (see to_display_score in
  // src/scoring.py), so trust is simply its inverse.
  const score = Math.min(Math.max(finding.score || 0, 0), 100);
  const trustLevel = 100 - score;

  // Confidence reflects how much verifiable evidence the offline engine had.
  // It is computed by the backend and is genuinely unknown for some messages,
  // in which case we say so rather than asserting a number.
  const confidenceScore =
    finding.confidence == null
      ? `N/A (${finding.confidence_label || 'Unknown'})`
      : `${finding.confidence}% (${finding.confidence_label || 'Unknown'})`;

  const getVerdictStyle = (level) => {
    if (level === 'High' || level === 'Critical') {
      return { label: 'HIGH RISK THREAT', badge: 'bg-red-950/80 text-red-300 border-red-800', border: 'border-red-900/60' };
    }
    if (level === 'Medium') {
      return { label: 'SUSPICIOUS MAIL', badge: 'bg-amber-950/80 text-amber-300 border-amber-800', border: 'border-amber-900/60' };
    }
    return { label: 'SAFE / LOW RISK', badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-800', border: 'border-emerald-900/60' };
  };

  const vStyle = getVerdictStyle(finding.risk_level);

  return (
    <div className={`p-6 bg-soc-card border-2 ${vStyle.border} rounded-2xl shadow-2xl space-y-6`}>
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-emerald-900/40 pb-4">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400 block">Verdict Evaluation</span>
          <h2 className="text-2xl font-extrabold text-white mt-0.5">{vStyle.label}</h2>
          <span className="text-xs font-mono text-cyan-400 block mt-1">Target Payload: {finding.file}</span>
        </div>
        <div className="flex items-center gap-3">
          <span className={`px-4 py-1.5 rounded-full font-mono font-extrabold text-xs uppercase tracking-wider border ${vStyle.badge}`}>
            {finding.risk_level} THREAT LEVEL
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono text-xs text-center">
        <div className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase block">Risk Score</span>
          <span className="text-2xl font-extrabold text-amber-400">{score} / 100</span>
        </div>
        <div className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase block">Sender Trust Level</span>
          <span className="text-2xl font-extrabold text-emerald-400">{trustLevel}%</span>
        </div>
        <div className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase block">Detection Confidence</span>
          <span className="text-sm font-bold text-cyan-300 block truncate" title={confidenceScore}>{confidenceScore}</span>
        </div>
        <div className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1">
          <span className="text-slate-400 text-[10px] uppercase block">Auth Status</span>
          <span className="text-sm font-bold text-slate-200 block uppercase">
            SPF: {finding.authentication?.spf?.toUpperCase() || 'NONE'}
          </span>
        </div>
      </div>
    </div>
  );
}

export default OverallVerdictBanner;
