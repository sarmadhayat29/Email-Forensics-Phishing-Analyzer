import React from 'react';
import { CheckCircle2 } from 'lucide-react';

function PhishingIndicatorCards({ signals }) {
  if (!signals || signals.length === 0) {
    return (
      <div className="p-4 bg-soc-bg border border-emerald-900/30 rounded-xl text-center text-xs text-slate-400 font-mono">
        <CheckCircle2 className="w-6 h-6 mx-auto text-emerald-400 mb-1" />
        No phishing indicators triggered.
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
      {signals.map((sig, idx) => {
        const title = sig.indicator || sig.signal || sig.title || 'Threat Finding';
        const weight = sig.weight || 0;
        const evidence = sig.evidence || sig.detail || '';
        const explanation = sig.explanation || sig.detail || '';
        const strength = (sig.strength || 'weak').toLowerCase();
        const isStrong = strength === 'strong';
        const contribution = sig.contribution_pct != null ? `${sig.contribution_pct}%` : null;
        const family = sig.family || '';

        return (
          <div key={idx} className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-2">
            <div className="flex items-center justify-between gap-2">
              <span className="font-bold text-slate-100">{title}</span>
              <div className="flex items-center gap-1.5 shrink-0">
                <span className={`px-2 py-0.5 text-[10px] font-bold rounded border ${
                  isStrong
                    ? 'bg-red-950 text-red-300 border-red-800'
                    : 'bg-slate-900 text-slate-400 border-slate-700'
                }`}>
                  {strength.toUpperCase()}
                </span>
                <span className="px-2.5 py-0.5 bg-red-950 text-red-300 border border-red-800 text-[11px] font-bold rounded">
                  +{weight} PTS
                </span>
              </div>
            </div>
            {(family || contribution) && (
              <div className="text-[10px] text-slate-500">
                {family && <span>Family: {family}</span>}
                {family && contribution && <span> · </span>}
                {contribution && <span>Contribution: {contribution}</span>}
              </div>
            )}
            <p className="text-slate-300 text-[11px] leading-snug">{explanation}</p>
            {evidence && (
              <code className="text-cyan-300 text-[10px] block pt-1 border-t border-emerald-950">
                Evidence: {evidence}
              </code>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default PhishingIndicatorCards;
