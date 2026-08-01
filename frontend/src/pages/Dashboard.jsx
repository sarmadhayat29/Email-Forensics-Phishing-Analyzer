import React from 'react';
import { UploadCloud, Shield, ArrowRight, Eye, Trash2 } from 'lucide-react';
import DownloadReportButton from '../components/common/DownloadReportButton';
import { useNavigate } from 'react-router-dom';
import { getSeverityBadge } from '../utils/formatters';
import { useHistory } from '../hooks/useHistory';

export default function Dashboard() {
  const navigate = useNavigate();
  const { historyList, deleteAnalysis } = useHistory();

  const highRiskCount = historyList.filter(h => h.risk_level === 'High' || h.risk_level === 'Critical').length;
  const mediumRiskCount = historyList.filter(h => h.risk_level === 'Medium').length;
  const safeCount = historyList.filter(h => h.risk_level === 'Low' || h.risk_level === 'Safe').length;

  return (
    <div className="space-y-6 sm:space-y-8">
      <div className="p-4 sm:p-6 lg:p-8 bg-soc-card border border-emerald-900/30 rounded-2xl sm:rounded-3xl shadow-2xl flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4 sm:gap-6">
        <div className="min-w-0">
          <h2 className="text-xl sm:text-2xl font-extrabold text-white break-words">Welcome back, SOC Analyst</h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">Local Workspace • Personal Investigation Environment</p>
        </div>
        <button
          onClick={() => navigate('/upload')}
          className="w-full sm:w-auto min-h-11 px-5 sm:px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold rounded-2xl text-xs uppercase tracking-wider transition flex items-center justify-center gap-2 shadow-lg shrink-0"
        >
          <UploadCloud className="w-4 h-4" /> Start New Email Investigation
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-6">
        <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl min-w-0">
          <span className="text-[10px] sm:text-xs font-mono text-slate-400 uppercase leading-snug block">Total Emails Analyzed</span>
          <span className="text-2xl sm:text-3xl font-extrabold text-white font-mono block mt-2">{historyList.length}</span>
        </div>
        <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl min-w-0">
          <span className="text-[10px] sm:text-xs font-mono text-slate-400 uppercase leading-snug block">High Risk Threats</span>
          <span className="text-2xl sm:text-3xl font-extrabold text-red-400 font-mono block mt-2">{highRiskCount}</span>
        </div>
        <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl min-w-0">
          <span className="text-[10px] sm:text-xs font-mono text-slate-400 uppercase leading-snug block">Medium Risk Emails</span>
          <span className="text-2xl sm:text-3xl font-extrabold text-amber-400 font-mono block mt-2">{mediumRiskCount}</span>
        </div>
        <div className="p-4 sm:p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl min-w-0">
          <span className="text-[10px] sm:text-xs font-mono text-slate-400 uppercase leading-snug block">Safe / Clean Emails</span>
          <span className="text-2xl sm:text-3xl font-extrabold text-emerald-400 font-mono block mt-2">{safeCount}</span>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <h3 className="font-bold text-slate-100 text-sm uppercase tracking-wider text-cyan-400">
            Recent Investigations ({historyList.length})
          </h3>
          <button onClick={() => navigate('/history')} className="text-xs text-emerald-400 font-mono hover:underline flex items-center gap-1 min-h-11 sm:min-h-0 self-start">
            View Full Analysis History <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {historyList.length === 0 ? (
          <div className="p-8 sm:p-10 bg-soc-card border border-emerald-900/30 rounded-2xl text-center text-xs text-slate-400 space-y-3">
            <Shield className="w-10 h-10 mx-auto text-emerald-500/40" />
            <p>No email investigations conducted yet. Upload an email file to begin forensic analysis.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6">
            {historyList.slice(0, 6).map((item) => (
              <div key={item.id} className="p-4 sm:p-5 bg-soc-card border border-emerald-900/30 hover:border-emerald-500/40 rounded-2xl shadow-xl flex flex-col justify-between transition space-y-4 group min-w-0">
                <div className="space-y-2 min-w-0">
                  <div className="flex items-center justify-between gap-2">
                    <span className="px-2.5 py-0.5 bg-soc-bg border border-emerald-900/60 font-mono text-slate-300 text-[11px] rounded truncate min-w-0 max-w-[55%]">
                      {item.filename}
                    </span>
                    <div className="shrink-0">{getSeverityBadge(item.risk_level)}</div>
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm break-words">{item.subject}</h4>
                  <span className="text-[11px] text-slate-400 block font-mono break-anywhere">From: {item.from_addr}</span>
                </div>

                <div className="pt-3 border-t border-emerald-950 flex items-center justify-between text-xs font-mono gap-2">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Score</span>
                    <span className="font-extrabold text-amber-400">{item.score} / 100</span>
                  </div>
                  <div className="text-right">
                    <span className="text-slate-500 block text-[10px]">Date</span>
                    <span className="text-slate-400">{item.date}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <button onClick={() => navigate(`/analysis/${item.id}`)} className="flex-1 min-h-11 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-xl font-bold text-xs transition flex items-center justify-center gap-1.5">
                    <Eye className="w-3.5 h-3.5" /> Quick View
                  </button>
                  <DownloadReportButton fileId={item.id} type="pdf" className="min-h-11 min-w-11 p-2 bg-soc-bg hover:bg-red-950/40 border border-red-800/40 text-red-400 rounded-xl inline-flex items-center justify-center" title="Download PDF Report" />
                  <button onClick={(e) => deleteAnalysis(item.id, e)} className="min-h-11 min-w-11 p-2 bg-soc-bg hover:bg-red-950/40 border border-slate-800 text-slate-400 hover:text-red-400 rounded-xl transition inline-flex items-center justify-center" title="Delete Entry">
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
