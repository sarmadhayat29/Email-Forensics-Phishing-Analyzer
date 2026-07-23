import React from 'react';

function RiskOverviewGauge({ score }) {
  const normalizedScore = Math.min(Math.max(score, 0), 1000);
  const percentage = normalizedScore / 1000;
  const radius = 65;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - percentage * circumference;

  const getBucket = (s) => {
    if (s >= 700) return { label: 'CRITICAL SEVERITY', color: 'text-red-500', bar: '#ef4444' };
    if (s >= 300) return { label: 'HIGH SEVERITY', color: 'text-red-400', bar: '#ef4444' };
    if (s >= 100) return { label: 'MEDIUM SEVERITY', color: 'text-amber-400', bar: '#f59e0b' };
    return { label: 'LOW / SAFE', color: 'text-emerald-400', bar: '#10b981' };
  };

  const bucket = getBucket(score);

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
          <span className="text-[10px] font-mono text-slate-400 uppercase">/ 1000 PTS</span>
        </div>
      </div>

      <div className="flex-1 space-y-3 font-mono text-xs w-full">
        <div className="flex items-center justify-between border-b border-emerald-900/40 pb-2">
          <span className="text-slate-400">Threat Bucket Category:</span>
          <span className={`font-extrabold uppercase ${bucket.color}`}>{bucket.label}</span>
        </div>

        <div className="space-y-2 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Critical Threat (700-1000)</span>
            <span className={score >= 700 ? "text-red-400 font-bold" : "text-slate-600"}>{score >= 700 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">High Threat (300-699)</span>
            <span className={score >= 300 && score < 700 ? "text-red-400 font-bold" : "text-slate-600"}>{score >= 300 && score < 700 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Medium Threat (100-299)</span>
            <span className={score >= 100 && score < 300 ? "text-amber-400 font-bold" : "text-slate-600"}>{score >= 100 && score < 300 ? "ACTIVE" : "CLEAN"}</span>
          </div>
          <div className="flex items-center justify-between">
            <span className="text-slate-400">Low / Safe (0-99)</span>
            <span className={score < 100 ? "text-emerald-400 font-bold" : "text-slate-600"}>{score < 100 ? "ACTIVE" : "CLEAN"}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default RiskOverviewGauge;
