import React from 'react';
import { UploadCloud, RefreshCw, CheckCircle2, Activity } from 'lucide-react';

export default function UploadPage({ 
  uploadProgress, 
  filename, 
  finding, 
  analysisSteps, 
  analysisStep, 
  fileInputRef, 
  handleDrop, 
  handleFileChange 
}) {
  return (
    <div className="max-w-2xl mx-auto py-8 space-y-6">
      {uploadProgress > 0 && uploadProgress < 100 ? (
        <div className="p-8 bg-[#121814] border border-emerald-900/40 rounded-3xl text-center shadow-2xl">
          <UploadCloud className="w-12 h-12 mx-auto text-emerald-400 animate-bounce mb-3" />
          <h3 className="text-lg font-bold text-slate-100">Uploading Payload {filename}</h3>
          <div className="w-full bg-[#0B0F0D] h-3 rounded-full overflow-hidden border border-emerald-950 my-4">
            <div className="bg-emerald-500 h-full transition-all duration-150 rounded-full" style={{ width: `${uploadProgress}%` }}></div>
          </div>
          <span className="text-xs font-mono text-emerald-400 font-bold">{uploadProgress}% Upload Completed</span>
        </div>
      ) : uploadProgress === 100 && !finding ? (
        <div className="p-8 bg-[#121814] border border-emerald-900/40 rounded-3xl text-center shadow-2xl">
          <RefreshCw className="w-12 h-12 mx-auto text-emerald-400 animate-spin mb-3" />
          <h3 className="text-lg font-bold text-slate-100 mb-1">Analyzing Forensic Payload</h3>
          <p className="text-xs font-mono text-cyan-400 mb-6">{analysisSteps[analysisStep]}</p>
          
          <div className="space-y-2.5 text-left bg-[#0B0F0D] p-5 rounded-2xl border border-emerald-950 text-xs font-mono">
            {analysisSteps.map((stepText, idx) => (
              <div key={idx} className="flex items-center gap-3">
                {idx < analysisStep ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : idx === analysisStep ? (
                  <Activity className="w-4 h-4 text-cyan-400 animate-spin shrink-0" />
                ) : (
                  <div className="w-4 h-4 rounded-full border border-emerald-900 shrink-0" />
                )}
                <span className={idx <= analysisStep ? "text-slate-200 font-bold" : "text-slate-600"}>{stepText}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div
          className="p-12 border-2 border-dashed border-emerald-900/60 hover:border-emerald-500 bg-[#121814] hover:bg-[#16221c] rounded-3xl cursor-pointer text-center transition group shadow-2xl"
          onClick={() => fileInputRef.current?.click()} onDrop={handleDrop} onDragOver={e => e.preventDefault()}
        >
          <input type="file" ref={fileInputRef} onChange={handleFileChange} accept=".eml,.msg" className="hidden" />
          <div className="w-16 h-16 mx-auto mb-4 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl flex items-center justify-center text-emerald-400 group-hover:scale-110 transition">
            <UploadCloud className="w-8 h-8" />
          </div>
          <h3 className="text-lg font-bold text-slate-100 mb-1">Upload Target Email Payload</h3>
          <p className="text-xs text-slate-400 font-mono">Drag &amp; drop raw <code className="text-emerald-400">.eml</code> or Outlook <code className="text-emerald-400">.msg</code> files</p>
        </div>
      )}
    </div>
  );
}
