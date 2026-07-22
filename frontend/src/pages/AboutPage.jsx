import React from 'react';

export default function AboutPage() {
  return (
    <div className="max-w-3xl mx-auto space-y-6">
      <div className="p-6 bg-[#121814] border border-emerald-900/30 rounded-2xl">
        <h3 className="font-bold text-slate-100 text-sm uppercase tracking-wider mb-2 text-cyan-400">About Email Forensics Platform</h3>
        <p className="text-xs text-slate-300 leading-relaxed mb-4">
          Built using clean architecture and SOLID principles. Operates 100% offline with zero external API dependencies.
        </p>
        <div className="space-y-2 text-xs font-mono text-slate-400">
          <p>✔ Commercial Cybersecurity Incident Investigation Screen</p>
          <p>✔ 10 Dedicated Forensic Investigation Sections</p>
          <p>✔ Persistent Database Analysis History (Supabase PostgreSQL / SQLite)</p>
          <p>✔ 12-Category Header Forensics Engine</p>
          <p>✔ SPF / DKIM / DMARC Alignment Verification</p>
          <p>✔ Hop-by-Hop Email Delivery Routing Timeline</p>
          <p>✔ 15-Category Weighted Phishing Scoring Engine</p>
          <p>✔ Multi-Format HTML, JSON &amp; PDF Report Generation</p>
        </div>
      </div>
    </div>
  );
}
