import React from 'react';
import { Mail, Activity, Lock, FileCode, Server, Link as LinkIcon, Paperclip, AlertOctagon, Zap } from 'lucide-react';
import SectionCard from '../components/ui/SectionCard';
import OverallVerdictBanner from '../components/investigation/OverallVerdictBanner';
import EmailSummaryGrid from '../components/investigation/EmailSummaryGrid';
import RiskOverviewGauge from '../components/investigation/RiskOverviewGauge';
import AuthForensicsCard from '../components/investigation/AuthForensicsCard';
import HeaderAnalysisAccordion from '../components/investigation/HeaderAnalysisAccordion';
import SearchableURLTable from '../components/investigation/SearchableURLTable';
import AttachmentForensicsGrid from '../components/investigation/AttachmentForensicsGrid';
import PhishingIndicatorCards from '../components/investigation/PhishingIndicatorCards';
import AnalystRecommendationBox from '../components/investigation/AnalystRecommendationBox';

export default function InvestigationScreen({ finding }) {
  if (!finding) return null;

  return (
    <div className="space-y-6">
      <OverallVerdictBanner finding={finding} />

      <SectionCard title="1. Email Metadata & Payload Summary" icon={Mail} defaultOpen={true}>
        <EmailSummaryGrid finding={finding} />
      </SectionCard>

      <SectionCard title="2. Risk Overview Category Gauge" icon={Activity} defaultOpen={true}>
        <RiskOverviewGauge score={finding.score} />
      </SectionCard>

      <SectionCard title="3. Authentication Analysis (SPF / DKIM / DMARC)" icon={Lock} defaultOpen={true}>
        <AuthForensicsCard auth={finding.authentication} />
      </SectionCard>

      <SectionCard title="4. Header Forensics Anomaly Cards" icon={FileCode} defaultOpen={true} badgeCount={finding.header_findings?.length || 0}>
        <HeaderAnalysisAccordion findings={finding.header_findings} />
      </SectionCard>

      <SectionCard title="5. Visual Email Delivery Routing Timeline" icon={Server} defaultOpen={true} badgeCount={finding.routing?.hop_count || 0}>
        <div className="space-y-4 font-mono text-xs">
          <div className="relative pl-6 space-y-4 border-l-2 border-emerald-900/50">
            {finding.routing?.timeline?.map((hop, idx) => (
              <div key={idx} className="relative">
                <div className="absolute -left-[31px] top-0.5 w-4 h-4 rounded-full bg-emerald-950 border-2 border-emerald-500 flex items-center justify-center text-emerald-400" />
                <div className="p-3.5 bg-[#0B0F0D] border border-emerald-900/40 rounded-xl space-y-1.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-emerald-400">Hop #{hop.hop_number} Relay</span>
                    <span className="text-slate-400">{hop.timestamp} ({hop.delay_display})</span>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-[11px]">
                    <div><span className="text-slate-500 block text-[10px]">From</span><span className="text-slate-200 font-bold truncate block">{hop.from_host}</span></div>
                    <div><span className="text-slate-500 block text-[10px]">By</span><span className="text-slate-200 font-bold truncate block">{hop.by_host}</span></div>
                    <div><span className="text-slate-500 block text-[10px]">IP</span><span className="text-cyan-300 truncate block">{hop.ip_info}</span></div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </SectionCard>

      <SectionCard title="7. Extracted Link Targets & URL Inspection Table" icon={LinkIcon} defaultOpen={true} badgeCount={finding.url_analysis?.total_urls || 0}>
        <SearchableURLTable urlAnalysis={finding.url_analysis} />
      </SectionCard>

      <SectionCard title="8. Attachment Binary Signature Forensics" icon={Paperclip} defaultOpen={true} badgeCount={finding.attachments?.length || 0}>
        <AttachmentForensicsGrid attachments={finding.attachments} embeddedImages={finding.embedded_images} />
      </SectionCard>

      <SectionCard title="9. Independent Phishing Threat Indicators" icon={AlertOctagon} defaultOpen={true} badgeCount={finding.signals?.length || 0}>
        <PhishingIndicatorCards signals={finding.signals} />
      </SectionCard>

      <SectionCard title="10. Executive SOC Analyst Conclusion & Incident Response Playbook" icon={Zap} defaultOpen={true}>
        <AnalystRecommendationBox finding={finding} />
      </SectionCard>
    </div>
  );
}
