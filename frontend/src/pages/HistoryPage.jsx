import React from 'react';
import { Search, ArrowUpDown, Trash2 } from 'lucide-react';
import { getSeverityBadge } from '../utils/formatters';

export default function HistoryPage({
  historyList,
  historySearch,
  setHistorySearch,
  historyFilter,
  setHistoryFilter,
  historySort,
  setHistorySort,
  openPreviousAnalysis,
  deleteAnalysis
}) {
  return (
    <div className="space-y-6">
      <div className="p-6 bg-[#121814] border border-emerald-900/30 rounded-2xl flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
          <input
            type="text" value={historySearch} onChange={e => setHistorySearch(e.target.value)}
            placeholder="Search by filename, subject, or sender..."
            className="w-full bg-[#0B0F0D] border border-emerald-900/40 rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex items-center gap-1.5 bg-[#0B0F0D] p-1 rounded-xl border border-emerald-900/30 text-xs font-mono font-bold">
          {['All', 'High', 'Medium', 'Safe'].map(f => (
            <button
              key={f} onClick={() => setHistoryFilter(f)}
              className={`px-3 py-1.5 rounded-lg transition ${historyFilter === f ? 'bg-emerald-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'}`}
            >
              {f}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <ArrowUpDown className="w-4 h-4 text-emerald-400" />
          <select
            value={historySort} onChange={e => setHistorySort(e.target.value)}
            className="bg-[#0B0F0D] border border-emerald-900/40 rounded-xl px-3 py-2 text-slate-100 focus:outline-none focus:border-emerald-500"
          >
            <option value="date_desc">Newest First</option>
            <option value="date_asc">Oldest First</option>
            <option value="score_desc">Highest Risk Score</option>
            <option value="score_asc">Lowest Risk Score</option>
            <option value="filename">Filename (A-Z)</option>
          </select>
        </div>
      </div>

      <div className="p-6 bg-[#121814] border border-emerald-900/30 rounded-2xl shadow-xl space-y-4">
        <h3 className="font-bold text-slate-100 text-xs uppercase tracking-wider text-cyan-400">
          Database Analysis History ({historyList.length} Entries)
        </h3>

        {historyList.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400 font-mono">No matching analysis records found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left font-mono">
              <thead>
                <tr className="border-b border-emerald-900/40 text-slate-400 uppercase">
                  <th className="py-2.5 px-3">Verdict</th>
                  <th className="py-2.5 px-3">Filename</th>
                  <th className="py-2.5 px-3">Subject</th>
                  <th className="py-2.5 px-3">Sender From</th>
                  <th className="py-2.5 px-3">Score</th>
                  <th className="py-2.5 px-3">Date</th>
                  <th className="py-2.5 px-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-emerald-950">
                {historyList.map(item => (
                  <tr key={item.id} className="hover:bg-[#0B0F0D] cursor-pointer" onClick={() => openPreviousAnalysis(item.id)}>
                    <td className="py-3 px-3">{getSeverityBadge(item.risk_level)}</td>
                    <td className="py-3 px-3 font-bold text-slate-200">{item.filename}</td>
                    <td className="py-3 px-3 text-slate-300 truncate max-w-xs">{item.subject}</td>
                    <td className="py-3 px-3 text-slate-400 truncate max-w-xs">{item.from_addr}</td>
                    <td className="py-3 px-3 text-amber-400 font-bold">{item.score}</td>
                    <td className="py-3 px-3 text-slate-400">{item.date}</td>
                    <td className="py-3 px-3 flex items-center gap-2">
                      <button onClick={() => openPreviousAnalysis(item.id)} className="px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded text-[11px] font-bold">
                        View
                      </button>
                      <a href={`/api/report/${item.id}/download/pdf`} target="_blank" rel="noreferrer" onClick={e => e.stopPropagation()} className="px-2.5 py-1 bg-red-950/40 text-red-400 border border-red-800/40 rounded text-[11px] font-bold">
                        PDF
                      </a>
                      <button onClick={e => deleteAnalysis(item.id, e)} className="p-1 text-slate-500 hover:text-red-400">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
