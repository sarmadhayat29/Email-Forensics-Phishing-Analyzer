import React, { useEffect, useState } from 'react';
import { Mail, Activity, Lock, FileCode, Server, Link as LinkIcon, Paperclip, AlertOctagon, Zap, ArrowLeft } from 'lucide-react';
import DownloadReportButton from '../components/common/DownloadReportButton';
import { useParams, useNavigate } from 'react-router-dom';
import { useAnalysis } from '../hooks/useAnalysis';
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
import LoadingScreen from '../components/ui/LoadingScreen';
import ErrorBanner from '../components/ui/ErrorBanner';

export default function InvestigationScreen() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { finding, loading, error, setError } = useAnalysis(id);

  if (loading) return <LoadingScreen message="Loading Forensic Data..." />;
  if (error) return <div className="p-8"><ErrorBanner error={error} onDismiss={() => setError(null)} /></div>;
  if (!finding) return (
    <div className="flex flex-col items-center justify-center py-24 gap-4 text-center">
      <p className="text-slate-400 font-mono text-sm">Investigation record not found or no longer available.</p>
      <button
        onClick={() => navigate('/history')}
        className="flex items-center gap-2 px-4 py-2 bg-soc-card border border-emerald-900/40 rounded-xl text-emerald-400 text-sm font-bold hover:bg-soc-hover transition"
      >
        <ArrowLeft className="w-4 h-4" /> Back to History
      </button>
    </div>
  );

  return (
    <div className="space-y-6">
      
      {/* Local header for actions since they were removed from App.jsx header */}
      <div className="flex items-center justify-between bg-soc-card p-4 rounded-2xl border border-emerald-900/40 shadow-xl mb-6">
        <div className="flex items-center gap-3">
          <h2 className="font-bold text-sm text-slate-100">Investigation Record</h2>
          <span className="px-2.5 py-0.5 bg-soc-bg border border-emerald-900/50 text-cyan-400 font-mono text-xs rounded">ID: {id.substring(0, 8)}</span>
        </div>
        <div className="flex items-center gap-2">
          <DownloadReportButton fileId={id} type="html" className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-slate-950 rounded-lg text-xs font-bold flex items-center gap-1.5">
            HTML
          </DownloadReportButton>
          <DownloadReportButton fileId={id} type="pdf" className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded-lg text-xs font-bold flex items-center gap-1.5">
            PDF
          </DownloadReportButton>
          <DownloadReportButton fileId={id} type="json" className="px-3 py-1.5 bg-soc-bg hover:bg-slate-800 border border-emerald-900/60 rounded-lg text-xs font-bold flex items-center gap-1.5 text-slate-200">
            <FileCode className="w-3.5 h-3.5" /> JSON
          </DownloadReportButton>
        </div>
      </div>

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
                <div className="p-3.5 bg-soc-bg border border-emerald-900/40 rounded-xl space-y-1.5">
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

      <SectionCard title="6. Extracted Link Targets & URL Inspection Table" icon={LinkIcon} defaultOpen={true} badgeCount={finding.url_analysis?.total_urls || 0}>
        <SearchableURLTable urlAnalysis={finding.url_analysis} />
      </SectionCard>

      <SectionCard title="7. Attachment Binary Signature Forensics" icon={Paperclip} defaultOpen={true} badgeCount={finding.attachments?.length || 0}>
        <AttachmentForensicsGrid attachments={finding.attachments} embeddedImages={finding.embedded_images} />
      </SectionCard>

      <SectionCard title="8. Independent Phishing Threat Indicators" icon={AlertOctagon} defaultOpen={true} badgeCount={finding.signals?.length || 0}>
        <PhishingIndicatorCards signals={finding.signals} />
      </SectionCard>

      <SectionCard title="9. Executive SOC Analyst Conclusion & Incident Response Playbook" icon={Zap} defaultOpen={true}>
        <AnalystRecommendationBox finding={finding} />
      </SectionCard>
    </div>
  );
}
