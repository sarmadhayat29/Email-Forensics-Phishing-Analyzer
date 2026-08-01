import React from 'react';
import {
  Shield, FileSearch, KeyRound, Route, ShieldAlert, Link2,
  Paperclip, Globe2, Code2, Scale, Database, FileDown, GraduationCap, Lock,
} from 'lucide-react';

const FEATURES = [
  {
    icon: FileSearch,
    title: 'Header forensics',
    text: 'Comprehensive email header forensic analysis for spoofing and structural anomalies.',
  },
  {
    icon: KeyRound,
    title: 'Authentication checks',
    text: 'Advanced SPF, DKIM, and DMARC verification with clear analyst-facing evidence.',
  },
  {
    icon: Route,
    title: 'Delivery routing',
    text: 'Hop-by-hop email delivery path analysis to reconstruct how a message arrived.',
  },
  {
    icon: ShieldAlert,
    title: 'Threat assessment',
    text: 'Intelligent phishing and threat risk assessment grounded in deterministic rules.',
  },
  {
    icon: Link2,
    title: 'URL analysis',
    text: 'URL inspection for deceptive links, lookalikes, and high-risk destinations.',
  },
  {
    icon: Paperclip,
    title: 'Attachment review',
    text: 'Attachment and sender reputation signals to surface risky payloads early.',
  },
  {
    icon: Globe2,
    title: 'Domain verification',
    text: 'Domain and email authentication verification to support identity decisions.',
  },
  {
    icon: Code2,
    title: 'HTML inspection',
    text: 'HTML email structure and content inspection for hidden or deceptive constructs.',
  },
  {
    icon: Scale,
    title: 'Explainable scoring',
    text: 'Explainable risk scoring with detailed forensic evidence for every finding.',
  },
  {
    icon: Database,
    title: 'Analysis history',
    text: 'Persistent analysis history using Supabase PostgreSQL or local SQLite storage.',
  },
  {
    icon: FileDown,
    title: 'Exportable reports',
    text: 'Export investigation reports in PDF, HTML, and JSON for case documentation.',
  },
  {
    icon: GraduationCap,
    title: 'Built for investigations',
    text: 'Designed for digital forensics, incident response, education, and email security work.',
  },
];

export default function AboutPage() {
  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Hero */}
      <section className="relative overflow-hidden p-6 sm:p-8 bg-soc-card border border-emerald-900/30 rounded-3xl shadow-xl">
        <div className="absolute -top-20 -right-16 w-56 h-56 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute -bottom-24 -left-10 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col sm:flex-row sm:items-start gap-5">
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 rounded-2xl text-emerald-400 shrink-0 w-fit">
            <Shield className="w-8 h-8" aria-hidden />
          </div>
          <div className="space-y-3 min-w-0">
            <p className="text-[10px] font-mono uppercase tracking-widest text-cyan-400">
              Product overview
            </p>
            <h1 className="text-xl sm:text-2xl font-extrabold text-slate-100 tracking-tight">
              About Email Forensics Platform
            </h1>
            <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
              A modern email forensics and threat analysis platform designed to help security
              professionals, students, and organizations investigate suspicious emails through
              comprehensive forensic analysis.
            </p>
            <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">
              Built with clean architecture and SOLID principles, the platform performs email
              analysis locally without relying on external AI services or third-party analysis APIs,
              providing fast, privacy-focused, and reliable investigations.
            </p>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="space-y-4">
        <div className="flex items-end justify-between gap-4 px-1">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-100">
              Key Features
            </h2>
            <p className="text-xs text-slate-500 mt-1">
              Practical forensic capabilities for day-to-day email investigations.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
          {FEATURES.map(({ icon: Icon, title, text }) => (
            <article
              key={title}
              className="p-4 sm:p-5 bg-soc-card border border-emerald-900/30 rounded-2xl hover:border-emerald-700/40 hover:bg-soc-hover transition"
            >
              <div className="flex items-start gap-3">
                <div className="p-2 bg-emerald-500/10 border border-emerald-500/20 rounded-xl text-emerald-400 shrink-0">
                  <Icon className="w-4 h-4" aria-hidden />
                </div>
                <div className="min-w-0 space-y-1.5">
                  <h3 className="text-sm font-bold text-slate-100">{title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{text}</p>
                </div>
              </div>
            </article>
          ))}
        </div>
      </section>

      {/* Privacy */}
      <section className="p-6 sm:p-8 bg-soc-card border border-emerald-900/30 rounded-3xl">
        <div className="flex flex-col sm:flex-row gap-4 sm:gap-6">
          <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-2xl text-cyan-400 shrink-0 w-fit h-fit">
            <Lock className="w-6 h-6" aria-hidden />
          </div>
          <div className="space-y-2">
            <h2 className="text-sm font-bold uppercase tracking-wider text-cyan-300">
              Privacy First
            </h2>
            <p className="text-sm text-slate-300 leading-relaxed max-w-3xl">
              All email analysis is performed inside the application.
            </p>
            <p className="text-sm text-slate-400 leading-relaxed max-w-3xl">
              No email content is sent to external AI providers or third-party email analysis
              services, helping protect sensitive information while delivering consistent forensic
              results.
            </p>
          </div>
        </div>
      </section>
    </div>
  );
}
