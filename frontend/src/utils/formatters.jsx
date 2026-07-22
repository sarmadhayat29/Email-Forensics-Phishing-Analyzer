import React from 'react';
import { CheckCircle2, AlertTriangle, AlertOctagon } from 'lucide-react';

export const getSeverityBadge = (level) => {
  switch (level) {
    case 'Critical':
    case 'High':
    case 'FAIL':
      return <span className="px-2.5 py-0.5 bg-red-950/80 text-red-300 border border-red-800 font-bold rounded text-xs uppercase tracking-wider flex items-center gap-1"><AlertOctagon className="w-3 h-3" /> {level}</span>;
    case 'Medium':
      return <span className="px-2.5 py-0.5 bg-amber-950/80 text-amber-300 border border-amber-800 font-bold rounded text-xs uppercase tracking-wider flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> {level}</span>;
    case 'Low':
    case 'Safe':
    case 'PASS':
    case 'CLEAN':
      return <span className="px-2.5 py-0.5 bg-emerald-950/80 text-emerald-300 border border-emerald-800 font-bold rounded text-xs uppercase tracking-wider flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> {level}</span>;
    default:
      return <span className="px-2.5 py-0.5 bg-slate-800 text-slate-300 border border-slate-700 font-bold rounded text-xs uppercase tracking-wider">{level}</span>;
  }
};
