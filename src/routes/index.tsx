import { createFileRoute } from "@tanstack/react-router";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Toaster } from "@/components/ui/sonner";
import { toast } from "sonner";
import { SafetyNote } from "@/components/SafetyNote";
import { AnalysisInput } from "@/components/AnalysisInput";
import { AnalysisResultView } from "@/components/AnalysisResult";
import { analyzeObservation, type AnalysisResult } from "@/lib/analyze.functions";
import { ShieldCheck, Search, Clock, BarChart3 } from "lucide-react";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "ATT&CKLens — Defensive MITRE ATT&CK Analyzer" },
      {
        name: "description",
        content:
          "Defensive SOC analyzer: paste a synthetic observation and get structured MITRE ATT&CK mapping, evidence, confidence, detection ideas, and remediation.",
      },
      { property: "og:title", content: "ATT&CKLens — Defensive MITRE ATT&CK Analyzer" },
      {
        property: "og:description",
        content:
          "Defensive-only ATT&CK analysis for logs, alerts, Nmap, packets, and SOC notes.",
      },
    ],
  }),
  component: App,
});

function App() {
  const analyze = useServerFn(analyzeObservation);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const handle = async (
    observationType: "log" | "alert" | "nmap" | "packet" | "soc" | "other",
    text: string,
  ) => {
    setLoading(true);
    setResult(null);
    try {
      const r = await analyze({ data: { observationType, text } });
      setResult(r);
    } catch (e: any) {
      const msg = String(e?.message ?? e);
      if (msg.includes("429")) toast.error("Rate limited — please wait and try again.");
      else if (msg.includes("402")) toast.error("AI credits exhausted for this workspace.");
      else toast.error("Analysis failed: " + msg.slice(0, 160));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen w-full overflow-hidden bg-[#0a0a1a] text-[#a0a0c0]">
      <Toaster richColors position="top-right" theme="dark" />

      {/* Sidebar */}
      <aside className="hidden w-64 shrink-0 flex-col border-r border-[#1e1e5a] bg-[#141432] lg:flex">
        <div className="flex items-center gap-3 border-b border-[#1e1e5a] p-6">
          <div className="flex h-8 w-8 items-center justify-center rounded bg-[#4f46e5] text-white">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <span className="font-mono-display text-xl font-bold uppercase tracking-tight text-white">
            ATT&amp;CKLens
          </span>
        </div>

        <nav className="flex-1 space-y-2 px-4 py-6">
          <a
            href="#"
            className="flex items-center gap-3 rounded-lg border border-[#4f46e5]/20 bg-[#4f46e5]/10 px-4 py-3 text-[#4f46e5]"
          >
            <Search className="h-5 w-5" />
            <span className="font-medium">Analyze</span>
          </a>
          <a
            href="#"
            className="flex items-center gap-3 rounded-lg px-4 py-3 text-slate-400 transition-colors hover:bg-[#1e1e5a] hover:text-white"
          >
            <Clock className="h-5 w-5" />
            <span>History</span>
          </a>
          <a
            href="#"
            className="flex items-center gap-3 rounded-lg px-4 py-3 text-slate-400 transition-colors hover:bg-[#1e1e5a] hover:text-white"
          >
            <BarChart3 className="h-5 w-5" />
            <span>Statistics</span>
          </a>
        </nav>

        <div className="font-mono-display border-t border-[#1e1e5a] p-6 text-[10px] uppercase tracking-widest text-slate-500">
          Build 0.4.2-DEF
        </div>
      </aside>

      {/* Main */}
      <main className="flex min-h-screen flex-1 flex-col">
        <header className="flex h-16 items-center justify-between border-b border-[#1e1e5a] bg-[#0a0a1a] px-8">
          <div className="font-mono-display flex items-center gap-4 text-sm font-medium uppercase tracking-wide text-slate-400">
            <span className="text-[#4f46e5]">SOC Analyzer</span>
            <span className="text-[#1e1e5a]">/</span>
            <span>New Observation</span>
          </div>
          <div className="flex items-center gap-6">
            <div className="font-mono-display flex items-center gap-2 text-[11px] uppercase tracking-wider text-slate-500">
              <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
              Threat Database Online
            </div>
            <div className="h-8 w-8 rounded-full border border-[#4f46e5]/30 bg-[#1e1e5a]" />
          </div>
        </header>

        <div className="mx-8 mt-6">
          <SafetyNote />
        </div>

        <div className="grid flex-1 grid-cols-1 gap-6 p-8 lg:grid-cols-12">
          <div className="lg:col-span-5">
            <AnalysisInput loading={loading} onAnalyze={handle} />
          </div>

          <div className="lg:col-span-7">
            {!result && !loading && (
              <section className="flex h-full min-h-[500px] items-center justify-center rounded-xl border-2 border-dashed border-[#1e1e5a] bg-[#0a0a1a]">
                <div className="max-w-sm text-center">
                  <div className="relative mb-6 inline-block">
                    <div className="absolute inset-0 bg-[#4f46e5] opacity-20 blur-2xl" />
                    <ShieldCheck
                      className="relative h-16 w-16 text-[#1e1e5a]"
                      strokeWidth={1}
                    />
                  </div>
                  <h3 className="font-mono-display mb-2 text-lg font-bold uppercase text-white">
                    Analysis Engine Idle
                  </h3>
                  <p className="text-sm leading-relaxed text-slate-500">
                    Awaiting observation data. Input a synthetic log entry or load a sample
                    to generate MITRE ATT&amp;CK mapping, confidence metrics, and
                    remediation paths.
                  </p>
                  <div className="mt-8 flex justify-center gap-1">
                    <div className="h-1 w-1 rounded-full bg-[#1e1e5a]" />
                    <div className="h-1 w-1 rounded-full bg-[#1e1e5a]" />
                    <div className="h-1 w-1 rounded-full bg-[#1e1e5a]" />
                  </div>
                </div>
              </section>
            )}

            {loading && (
              <section className="flex h-full min-h-[500px] items-center justify-center rounded-xl border border-[#1e1e5a] bg-[#141432]">
                <div className="text-center">
                  <div className="mx-auto mb-4 h-10 w-10 animate-spin rounded-full border-2 border-[#1e1e5a] border-t-[#4f46e5]" />
                  <p className="font-mono-display text-sm uppercase tracking-widest text-slate-400">
                    Running defensive analysis...
                  </p>
                </div>
              </section>
            )}

            {result && <AnalysisResultView result={result} />}
          </div>
        </div>

        <footer className="font-mono-display flex items-center justify-between border-t border-[#1e1e5a] bg-[#141432] px-8 py-3 text-[10px] font-medium uppercase tracking-widest text-slate-500">
          <div>System Health: Nominal</div>
          <div>Educational · Defensive · Authorized lab use only · Synthetic data</div>
        </footer>
      </main>
    </div>
  );
}
