import React from 'react';
import { Zap } from 'lucide-react';

function AnalystRecommendationBox({ finding }) {
  const isMalicious = finding.risk_level === 'High' || finding.risk_level === 'Critical';

  return (
    <div className="p-5 bg-[#0B0F0D] border-2 border-emerald-500/40 rounded-xl space-y-3 font-mono text-xs">
      <div className="flex items-center gap-2">
        <Zap className="w-4 h-4 text-emerald-400" />
        <span className="font-bold text-slate-100 uppercase tracking-wider">SOC Incident Response Playbook Conclusion</span>
      </div>

      {isMalicious ? (
        <ul className="space-y-2 text-slate-300 text-[11px] list-disc list-inside">
          <li><strong className="text-red-400">Immediate Inbox Purge:</strong> Execute Microsoft 365 / Google Workspace tenant search &amp; purge for Message-ID <code>{finding.message_id || 'payload'}</code>.</li>
          <li><strong className="text-red-400">Perimeter Blocking:</strong> Add sender domain <code>{finding.from_addr}</code> to Email Gateway blocklists.</li>
          <li><strong className="text-red-400">Network Containment:</strong> Block extracted malicious target URLs/IPs on Proxy and Firewall.</li>
          <li><strong className="text-red-400">Credential Safeguard:</strong> Revoke active SSO sessions and force password reset for impacted users.</li>
        </ul>
      ) : (
        <p className="text-slate-300 text-[11px] leading-relaxed">
          <strong className="text-emerald-400">Low Threat Verdict:</strong> Email satisfied SPF/DKIM/DMARC authentication standards and exhibited low risk indicators. No automated incident response containment required.
        </p>
      )}
    </div>
  );
}

export default AnalystRecommendationBox;
