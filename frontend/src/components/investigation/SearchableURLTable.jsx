import React, { useState } from 'react';
import { Search, CheckCircle2, AlertTriangle, Copy, Check } from 'lucide-react';

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async (e) => {
    e.stopPropagation();
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button onClick={handleCopy} className="ml-1 text-slate-500 hover:text-emerald-400 transition" title="Copy raw URL">
      {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
    </button>
  );
}

function defang(url) {
  return url.replace(/^https?:\/\//i, (m) => m.replace('://', '[://]').replace('http', 'hxxp'));
}

function SearchableURLTable({ urlAnalysis }) {
  const [searchQuery, setSearchQuery] = useState('');

  if (!urlAnalysis || !urlAnalysis.urls || urlAnalysis.urls.length === 0) {
    return (
      <div className="p-4 bg-soc-bg border border-emerald-900/30 rounded-xl text-center text-xs text-slate-400 font-mono">
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
          type="search" value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
          placeholder="Filter URLs by host domain, target URL, or anchor text..."
          className="w-full min-h-11 bg-soc-bg border border-emerald-900/40 rounded-xl pl-9 pr-3 py-2.5 text-slate-100 focus:outline-none focus:border-emerald-500"
        />
      </div>

      <div className="overflow-x-auto -mx-1 px-1">
        <table className="w-full min-w-[560px] text-xs text-left font-mono">
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
                <tr key={idx} className="hover:bg-soc-bg">
                  <td className="py-3 px-3 text-cyan-400 truncate max-w-md">
                    {/* Defanged: no live link — prevents accidental click on malicious URLs */}
                    <span className="flex items-center gap-1">
                      <code className="truncate text-xs text-cyan-300 bg-soc-bg px-1 py-0.5 rounded">
                        {defang(u.normalized_url)}
                      </code>
                      <CopyButton text={u.normalized_url} />
                    </span>
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
