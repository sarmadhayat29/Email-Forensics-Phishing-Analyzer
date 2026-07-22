import React, { useState } from 'react';
import { Search, CheckCircle2, AlertTriangle, Link as LinkIcon } from 'lucide-react';

function SearchableURLTable({ urlAnalysis }) {
  const [searchQuery, setSearchQuery] = useState('');

  if (!urlAnalysis || !urlAnalysis.urls || urlAnalysis.urls.length === 0) {
    return (
      <div className="p-4 bg-[#0B0F0D] border border-emerald-900/30 rounded-xl text-center text-xs text-slate-400 font-mono">
        No URLs extracted from message HTML or text body.
      </div>
    );
  }

  const filteredUrls = urlAnalysis.urls.filter(u =>
    u.normalized_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
    u.domain.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (u.anchor_text && u.anchor_text.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  return (
    <div className="space-y-4 font-mono text-xs">
      <div className="relative">
        <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
        <input
          type="text" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
          placeholder="Filter URLs by host domain, target URL, or anchor text..."
          className="w-full bg-[#0B0F0D] border border-emerald-900/40 rounded-xl pl-9 pr-3 py-2 text-slate-100 focus:outline-none focus:border-emerald-500"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-xs text-left font-mono">
          <thead>
            <tr className="border-b border-emerald-900/40 text-slate-400 uppercase">
              <th className="py-2.5 px-3">Normalized Target URL</th>
              <th className="py-2.5 px-3">Host Domain</th>
              <th className="py-2.5 px-3">Anchor Text</th>
              <th className="py-2.5 px-3">Risk &amp; Reason</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-emerald-950">
            {filteredUrls.map((u, idx) => {
              const hasFindings = u.findings && u.findings.length > 0;

              return (
                <tr key={idx} className="hover:bg-[#0B0F0D]">
                  <td className="py-3 px-3 text-cyan-400 truncate max-w-md">
                    <a href={u.normalized_url} target="_blank" rel="noreferrer" className="hover:underline flex items-center gap-1">
                      <LinkIcon className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">{u.normalized_url}</span>
                    </a>
                  </td>
                  <td className="py-3 px-3 text-slate-200 font-bold">{u.domain}</td>
                  <td className="py-3 px-3 text-slate-400">{u.anchor_text || '(None)'}</td>
                  <td className="py-3 px-3">
                    {hasFindings ? (
                      <div className="space-y-1 text-amber-300 font-bold">
                        {u.findings.map((fText, fIdx) => (
                          <div key={fIdx} className="flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
                            <span>{fText}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <span className="text-emerald-400 font-bold flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> CLEAN
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default SearchableURLTable;
