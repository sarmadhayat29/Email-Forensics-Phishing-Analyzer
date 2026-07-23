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
    <div className="space-y-8">
      <div className="p-8 bg-soc-card border border-emerald-900/30 rounded-3xl shadow-2xl flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
        <div>
          <h2 className="text-2xl font-extrabold text-white">Welcome back, SOC Analyst</h2>
          <p className="text-xs text-slate-400 mt-1 font-mono">Local Workspace • Personal Investigation Environment</p>
        </div>
        <button onClick={() => navigate('/upload')} className="px-6 py-3 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-extrabold rounded-2xl text-xs uppercase tracking-wider transition flex items-center gap-2 shadow-lg">
          <UploadCloud className="w-4 h-4" /> Start New Email Investigation
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl">
          <span className="text-xs font-mono text-slate-400 uppercase">Total Emails Analyzed</span>
          <span className="text-3xl font-extrabold text-white font-mono block mt-2">{historyList.length}</span>
        </div>
        <div className="p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl">
          <span className="text-xs font-mono text-slate-400 uppercase">High Risk Threats</span>
          <span className="text-3xl font-extrabold text-red-400 font-mono block mt-2">{highRiskCount}</span>
        </div>
        <div className="p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl">
          <span className="text-xs font-mono text-slate-400 uppercase">Medium Risk Emails</span>
          <span className="text-3xl font-extrabold text-amber-400 font-mono block mt-2">{mediumRiskCount}</span>
        </div>
        <div className="p-6 bg-soc-card border border-emerald-900/30 rounded-2xl shadow-xl">
          <span className="text-xs font-mono text-slate-400 uppercase">Safe / Clean Emails</span>
          <span className="text-3xl font-extrabold text-emerald-400 font-mono block mt-2">{safeCount}</span>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="font-bold text-slate-100 text-sm uppercase tracking-wider text-cyan-400">
            Recent Investigation Workspace Cards ({historyList.length})
          </h3>
          <button onClick={() => navigate('/history')} className="text-xs text-emerald-400 font-mono hover:underline flex items-center gap-1">
            View Full Analysis History <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {historyList.length === 0 ? (
          <div className="p-10 bg-soc-card border border-emerald-900/30 rounded-2xl text-center text-xs text-slate-400 space-y-3">
            <Shield className="w-10 h-10 mx-auto text-emerald-500/40" />
            <p>No email investigations conducted yet. Upload an email file to begin forensic analysis.</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {historyList.slice(0, 6).map((item) => (
              <div key={item.id} className="p-5 bg-soc-card border border-emerald-900/30 hover:border-emerald-500/40 rounded-2xl shadow-xl flex flex-col justify-between transition space-y-4 group">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="px-2.5 py-0.5 bg-soc-bg border border-emerald-900/60 font-mono text-slate-300 text-[11px] rounded truncate max-w-[150px]">
                      {item.filename}
                    </span>
                    {getSeverityBadge(item.risk_level)}
                  </div>
                  <h4 className="font-bold text-slate-100 text-sm truncate">{item.subject}</h4>
                  <span className="text-[11px] text-slate-400 block font-mono truncate">From: {item.from_addr}</span>
                </div>

                <div className="pt-3 border-t border-emerald-950 flex items-center justify-between text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Score</span>
                    <span className="font-extrabold text-amber-400">{item.score} / 1000</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Date</span>
                    <span className="text-slate-400">{item.date}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <button onClick={() => navigate(`/analysis/${item.id}`)} className="flex-1 py-2 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-xl font-bold text-xs transition flex items-center justify-center gap-1.5">
                    <Eye className="w-3.5 h-3.5" /> Quick View
                  </button>
                  <DownloadReportButton fileId={item.id} type="pdf" className="p-2 bg-soc-bg hover:bg-red-950/40 border border-red-800/40 text-red-400 rounded-xl" title="Download PDF Report" />
                  <button onClick={(e) => deleteAnalysis(item.id, e)} className="p-2 bg-soc-bg hover:bg-red-950/40 border border-slate-800 text-slate-400 hover:text-red-400 rounded-xl transition" title="Delete Entry">
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
