import React from 'react';
import { Search, ArrowUpDown, Trash2 } from 'lucide-react';
import DownloadReportButton from '../components/common/DownloadReportButton';
import { useNavigate } from 'react-router-dom';
import { getSeverityBadge } from '../utils/formatters';
import { useHistory } from '../hooks/useHistory';
import LoadingScreen from '../components/ui/LoadingScreen';
import ErrorBanner from '../components/ui/ErrorBanner';

export default function HistoryPage() {
  const navigate = useNavigate();
  const {
    historyList,
    loading,
    error,
    search, setSearch,
    sort, setSort,
    filter, setFilter,
    deleteAnalysis
  } = useHistory();

  return (
    <div className="space-y-4 sm:space-y-6">
      <ErrorBanner error={error} />

      <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl flex flex-col gap-4">
        <div className="relative w-full min-w-0">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by filename, subject, or sender..."
            className="w-full min-h-11 bg-soc-bg border border-emerald-900/40 rounded-xl pl-9 pr-3 py-2.5 text-xs font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
          <div className="flex items-center gap-1.5 bg-soc-bg p-1 rounded-xl border border-emerald-900/30 text-xs font-mono font-bold overflow-x-auto max-w-full">
            {['All', 'Critical', 'High', 'Medium', 'Safe'].map(f => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={`min-h-10 px-3 py-2 rounded-lg transition shrink-0 ${filter === f ? 'bg-emerald-500 text-slate-950 shadow' : 'text-slate-400 hover:text-slate-200'}`}
              >
                {f}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 text-xs font-mono min-w-0 sm:ml-auto">
            <ArrowUpDown className="w-4 h-4 text-emerald-400 shrink-0" />
            <select
              value={sort}
              onChange={e => setSort(e.target.value)}
              className="min-h-11 flex-1 sm:flex-none bg-soc-bg border border-emerald-900/40 rounded-xl px-3 py-2 text-slate-100 focus:outline-none focus:border-emerald-500 max-w-full"
            >
              <option value="date_desc">Newest First</option>
              <option value="date_asc">Oldest First</option>
              <option value="score_desc">Highest Risk Score</option>
              <option value="score_asc">Lowest Risk Score</option>
              <option value="filename">Filename (A-Z)</option>
            </select>
          </div>
        </div>
      </div>

      <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl space-y-4">
        <h3 className="font-bold text-slate-100 text-xs uppercase tracking-wider text-cyan-400">
          Database Analysis History ({historyList.length} Entries)
        </h3>

        {loading ? (
          <LoadingScreen message="Loading history..." />
        ) : historyList.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-400 font-mono">No matching analysis records found.</div>
        ) : (
          <>
            {/* Mobile card list */}
            <div className="md:hidden space-y-3">
              {historyList.map(item => (
                <div
                  key={item.id}
                  className="p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-3 cursor-pointer"
                  onClick={() => navigate(`/analysis/${item.id}`)}
                >
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0 space-y-1">
                      <p className="text-xs font-bold text-slate-100 break-words">{item.subject || '(No Subject)'}</p>
                      <p className="text-[11px] font-mono text-slate-400 truncate">{item.filename}</p>
                    </div>
                    {getSeverityBadge(item.risk_level)}
                  </div>
                  <p className="text-[11px] font-mono text-slate-400 break-anywhere">From: {item.from_addr}</p>
                  <div className="flex items-center justify-between gap-2 text-[11px] font-mono">
                    <span className="text-amber-400 font-bold">Score {item.score}</span>
                    <span className="text-slate-500">{item.date}</span>
                  </div>
                  <div className="flex items-center gap-2 pt-1" onClick={e => e.stopPropagation()}>
                    <button
                      type="button"
                      onClick={() => navigate(`/analysis/${item.id}`)}
                      className="flex-1 min-h-11 px-3 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-xl text-[11px] font-bold"
                    >
                      View
                    </button>
                    <DownloadReportButton
                      fileId={item.id}
                      type="pdf"
                      className="min-h-11 px-3 bg-red-950/40 text-red-400 border border-red-800/40 rounded-xl text-[11px] font-bold inline-flex items-center"
                    >
                      PDF
                    </DownloadReportButton>
                    <button
                      type="button"
                      onClick={e => deleteAnalysis(item.id, e)}
                      className="min-h-11 min-w-11 inline-flex items-center justify-center text-slate-500 hover:text-red-400"
                      aria-label="Delete analysis"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))}
            </div>

            {/* Desktop table */}
            <div className="hidden md:block overflow-x-auto -mx-1 px-1">
              <table className="w-full min-w-[640px] text-xs text-left font-mono">
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
                    <tr key={item.id} className="hover:bg-soc-bg cursor-pointer" onClick={() => navigate(`/analysis/${item.id}`)}>
                      <td className="py-3 px-3">{getSeverityBadge(item.risk_level)}</td>
                      <td className="py-3 px-3 font-bold text-slate-200 max-w-[10rem] truncate">{item.filename}</td>
                      <td className="py-3 px-3 text-slate-300 truncate max-w-[12rem]">{item.subject}</td>
                      <td className="py-3 px-3 text-slate-400 truncate max-w-[12rem]">{item.from_addr}</td>
                      <td className="py-3 px-3 text-amber-400 font-bold">{item.score}</td>
                      <td className="py-3 px-3 text-slate-400 whitespace-nowrap">{item.date}</td>
                      <td className="py-3 px-3">
                        <div className="flex items-center gap-2" onClick={e => e.stopPropagation()}>
                          <button
                            type="button"
                            onClick={() => navigate(`/analysis/${item.id}`)}
                            className="min-h-9 px-2.5 py-1 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded text-[11px] font-bold"
                          >
                            View
                          </button>
                          <DownloadReportButton fileId={item.id} type="pdf" className="min-h-9 px-2.5 py-1 bg-red-950/40 text-red-400 border border-red-800/40 rounded text-[11px] font-bold inline-flex items-center">
                            PDF
                          </DownloadReportButton>
                          <button
                            type="button"
                            onClick={e => deleteAnalysis(item.id, e)}
                            className="min-h-9 min-w-9 inline-flex items-center justify-center text-slate-500 hover:text-red-400"
                            aria-label="Delete analysis"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
