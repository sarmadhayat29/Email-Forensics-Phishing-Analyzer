import React, { useState } from 'react';
import { ChevronUp, ChevronDown } from 'lucide-react';

function SectionCard({ title, icon: Icon, defaultOpen = true, children, badgeCount = null }) {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="bg-[#121814] border border-emerald-900/30 rounded-2xl shadow-xl overflow-hidden transition">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-6 py-4 bg-[#121814] hover:bg-[#16221c] flex items-center justify-between transition border-b border-emerald-900/30 text-left"
      >
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-emerald-400">
            <Icon className="w-4 h-4" />
          </div>
          <h3 className="font-bold text-slate-100 text-sm uppercase tracking-wider">{title}</h3>
          {badgeCount !== null && (
            <span className="px-2.5 py-0.5 bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono text-[11px] font-bold rounded-full">
              {badgeCount}
            </span>
          )}
        </div>
        <div className="text-slate-400 hover:text-slate-200">
          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {isOpen && <div className="p-6 space-y-4">{children}</div>}
    </div>
  );
}

export default SectionCard;
