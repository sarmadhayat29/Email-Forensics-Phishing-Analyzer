import React from 'react';

function EmailSummaryGrid({ finding }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 text-xs font-mono">
      <div className="sm:col-span-2 p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Subject</span>
        <span className="font-bold text-slate-100 text-sm break-words block">{finding.subject || '(No Subject)'}</span>
      </div>
      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Sender (Header From)</span>
        <span className="font-bold text-slate-200 break-anywhere block">{finding.from_addr || '(Missing)'}</span>
      </div>
      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Recipient (To)</span>
        <span className="font-bold text-slate-200 break-anywhere block">{finding.to_addr || '(Missing)'}</span>
      </div>

      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Date &amp; Timestamp</span>
        <span className="font-bold text-slate-300 break-words block">{finding.date || '-'}</span>
      </div>
      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Attachments Extracted</span>
        <span className="font-bold text-emerald-400 block">{finding.attachments?.length || 0} File(s)</span>
      </div>
      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Extracted Links / URLs</span>
        <span className="font-bold text-cyan-400 block">{finding.url_analysis?.total_urls || 0} URL(s)</span>
      </div>
      <div className="p-3 sm:p-4 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1 min-w-0">
        <span className="text-[10px] text-slate-400 uppercase font-bold block">Message-ID Header</span>
        <span className="font-bold text-slate-300 break-anywhere block">{finding.message_id || '-'}</span>
      </div>
    </div>
  );
}

export default EmailSummaryGrid;
