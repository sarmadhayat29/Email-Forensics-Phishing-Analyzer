import React from 'react';
import { CheckCircle2 } from 'lucide-react';

function HeaderAnalysisAccordion({ findings }) {
  if (!findings || findings.length === 0) {
    return (
      <div className="p-4 bg-soc-bg border border-emerald-900/30 rounded-xl text-center text-xs text-slate-400 font-mono">
        <CheckCircle2 className="w-6 h-6 mx-auto text-emerald-400 mb-1" />
        No header spoofing or structural anomalies detected.
      </div>
    );
  }

  return (
    <div className="space-y-3 font-mono text-xs">
      {findings.map((hf, idx) => {
        const isHigh = hf.risk_level === 'High' || hf.risk_level === 'Critical';

        return (
          <div key={idx} className={`p-4 rounded-xl border space-y-2 ${isHigh ? 'bg-red-950/20 border-red-900/60' : 'bg-soc-bg border-emerald-900/40'}`}>
            <div className="flex items-center justify-between">
              <span className="font-bold text-slate-100">{hf.title}</span>
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded uppercase border ${isHigh ? 'bg-red-950 text-red-300 border-red-800' : 'bg-amber-950 text-amber-300 border-amber-800'}`}>
                {hf.risk_level} Severity
              </span>
            </div>

            <p className="text-slate-300 text-[11px] leading-snug">{hf.description}</p>

            <div className="pt-2 border-t border-emerald-900/30 space-y-1">
              <code className="text-cyan-300 text-[10px] block">Evidence: {hf.evidence}</code>
              <span className="text-emerald-400 text-[11px] block font-bold">Recommendation: {hf.recommendation}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default HeaderAnalysisAccordion;
