import React from 'react';

// Thresholds mirror the backend risk buckets in src/scoring.py (RISK_BUCKETS):
// Low < 30, Medium 30-69, High 70-89, Critical >= 90 on the 0-100 scale.
function RiskOverviewGauge({ score }) {
  const normalizedScore = Math.min(Math.max(score || 0, 0), 100);
  const percentage = normalizedScore / 100;
  const radius = 65;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - percentage * circumference;

  const getBucket = (s) => {
    if (s >= 90) return { label: 'CRITICAL SEVERITY', color: 'text-red-500', bar: '#ef4444' };
    if (s >= 70) return { label: 'HIGH SEVERITY', color: 'text-red-400', bar: '#ef4444' };
    if (s >= 30) return { label: 'MEDIUM SEVERITY', color: 'text-amber-400', bar: '#f59e0b' };
    return { label: 'LOW / SAFE', color: 'text-emerald-400', bar: '#10b981' };
  };

  const bucket = getBucket(normalizedScore);

  return (
    <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-4 bg-soc-bg border border-emerald-900/40 rounded-xl">
      <div className="relative w-40 h-40 flex items-center justify-center shrink-0">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 160 160">
          <circle cx="80" cy="80" r={radius} stroke="#16221c" strokeWidth="12" fill="transparent" />
          <circle
            cx="80" cy="80" r={radius}
            stroke={bucket.bar} strokeWidth="12"
            strokeDasharray={circumference} strokeDashoffset={strokeDashoffset}
            strokeLinecap="round" fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className={`text-3xl font-extrabold font-mono tracking-tight ${bucket.color}`}>
            {normalizedScore}
          </span>
          <span className="text-[10px] font-mono text-slate-400 uppercase">/ 100 PTS</span>
        </div>
      </div>

      <div className="flex-1 space-y-3 font-mono text-xs w-full">
        <div className="flex items-center justify-between border-b border-emerald-900/40 pb-2">
          <span className="text-slate-400">Threat Bucket Category:</span>
          <span className={`font-extrabold uppercase ${bucket.color}`}>{bucket.label}</span>
        </div>

        <div className="space-y-2 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Critical Threat (90-100)</span>
            <span className={normalizedScore >= 90 ? "text-red-400 font-bold" : "text-slate-600"}>{normalizedScore >= 90 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">High Threat (70-89)</span>
            <span className={normalizedScore >= 70 && normalizedScore < 90 ? "text-red-400 font-bold" : "text-slate-600"}>{normalizedScore >= 70 && normalizedScore < 90 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Medium Threat (30-69)</span>
            <span className={normalizedScore >= 30 && normalizedScore < 70 ? "text-amber-400 font-bold" : "text-slate-600"}>{normalizedScore >= 30 && normalizedScore < 70 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Low / Safe (0-29)</span>
            <span className={normalizedScore < 30 ? "text-emerald-400 font-bold" : "text-slate-600"}>{normalizedScore < 30 ? "ACTIVE" : "CLEAN"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default RiskOverviewGauge;
