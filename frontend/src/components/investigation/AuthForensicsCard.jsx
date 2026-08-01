import React from 'react';

function AuthForensicsCard({ auth }) {
  if (!auth) return null;

  const getBadgeStyle = (verdict) => {
    if (verdict === 'pass') return "bg-emerald-950 text-emerald-300 border-emerald-800";
    if (verdict === 'fail' || verdict === 'softfail') return "bg-red-950 text-red-300 border-red-800";
    return "bg-slate-800 text-slate-400 border-slate-700";
  };

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4">
        
        {/* SPF */}
        <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-2 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="font-bold text-slate-200">SPF Verification</span>
            <span className={`px-2 py-0.5 border text-[10px] font-bold rounded uppercase shrink-0 ${getBadgeStyle(auth.spf)}`}>
              {auth.spf?.toUpperCase() || 'NONE'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight break-words">{auth.spf_details || 'SPF record details unavailable.'}</p>
        </div>

        {/* DKIM */}
        <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-2 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="font-bold text-slate-200">DKIM Signature</span>
            <span className={`px-2 py-0.5 border text-[10px] font-bold rounded uppercase shrink-0 ${getBadgeStyle(auth.dkim)}`}>
              {auth.dkim?.toUpperCase() || 'NONE'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight break-words">{auth.dkim_details || 'DKIM signature verification details.'}</p>
        </div>

        {/* DMARC */}
        <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-2 min-w-0">
          <div className="flex items-center justify-between gap-2">
            <span className="font-bold text-slate-200">DMARC Policy</span>
            <span className={`px-2 py-0.5 border text-[10px] font-bold rounded uppercase shrink-0 ${getBadgeStyle(auth.dmarc)}`}>
              {auth.dmarc?.toUpperCase() || 'NONE'}
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-tight break-words">{auth.dmarc_details || 'DMARC policy alignment status.'}</p>
        </div>

      </div>

      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-2">
        <span className="font-bold text-cyan-400 uppercase text-[11px] block">Technical Explanation &amp; Recommendation</span>
        <p className="text-slate-300 text-[11px] leading-relaxed break-words">{auth.explanation}</p>
      </div>
    </div>
  );
}

export default AuthForensicsCard;
