import React from 'react';
import { CheckCircle2, AlertTriangle, Paperclip, Copy } from 'lucide-react';

function AttachmentForensicsGrid({ attachments, embeddedImages }) {
  const allFiles = [...(attachments || []), ...(embeddedImages || [])];

  if (allFiles.length === 0) {
    return (
      <div className="p-4 bg-soc-bg border border-emerald-900/30 rounded-xl text-center text-xs text-slate-400 font-mono">
        No attachments or embedded binary payloads found.
      </div>
    );
  }

  const copyHash = (hash) => {
    if (hash) navigator.clipboard.writeText(hash);
  };

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs text-left font-mono">
        <thead>
          <tr className="border-b border-emerald-900/40 text-slate-400 uppercase">
            <th className="py-2.5 px-3">Filename</th>
            <th className="py-2.5 px-3">Extension</th>
            <th className="py-2.5 px-3">True Signature</th>
            <th className="py-2.5 px-3">Size</th>
            <th className="py-2.5 px-3">SHA-256 Hash</th>
            <th className="py-2.5 px-3">Risk &amp; Reason</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-emerald-950">
          {allFiles.map((f, idx) => {
            const hasIssues = f.findings && f.findings.length > 0;

            return (
              <tr key={idx} className="hover:bg-soc-bg">
                <td className="py-3 px-3 font-bold text-slate-200 flex items-center gap-2">
                  <Paperclip className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span className="truncate max-w-xs">{f.filename}</span>
                </td>
                <td className="py-3 px-3 text-slate-400">.{f.declared_extension}</td>
                <td className="py-3 px-3">
                  <span className="px-2 py-0.5 bg-soc-bg border border-emerald-900/60 text-slate-200 rounded text-[11px]">
                    {f.true_type}
                  </span>
                </td>
                <td className="py-3 px-3 text-slate-300">{f.size_bytes} B</td>
                <td className="py-3 px-3">
                  {f.hashes?.sha256 ? (
                    <button onClick={() => copyHash(f.hashes.sha256)} className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px]" title="Click to copy full SHA-256">
                      <code>{f.hashes.sha256.substring(0, 12)}...</code>
                      <Copy className="w-3 h-3" />
                    </button>
                  ) : '-'}
                </td>
                <td className="py-3 px-3">
                  {hasIssues ? (
                    <div className="space-y-1 text-red-400 font-bold">
                      {f.findings.map((findingText, fIdx) => (
                        <div key={fIdx} className="flex items-center gap-1">
                          <AlertTriangle className="w-3 h-3 shrink-0" />
                          <span>{findingText}</span>
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
  );
}

export default AttachmentForensicsGrid;
