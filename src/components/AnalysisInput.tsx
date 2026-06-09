import { useState } from "react";
import { SAMPLES } from "./SampleObservations";
import { Loader2, Play } from "lucide-react";

type ObservationType = "log" | "alert" | "nmap" | "packet" | "soc" | "other";

const TYPE_OPTIONS: { value: ObservationType; label: string }[] = [
  { value: "log", label: "Raw Log Entry" },
  { value: "alert", label: "Alert" },
  { value: "nmap", label: "Nmap Output" },
  { value: "packet", label: "Packet Capture Snippet" },
  { value: "soc", label: "SOC Incident Note" },
  { value: "other", label: "Other" },
];

export function AnalysisInput({
  loading,
  onAnalyze,
}: {
  loading: boolean;
  onAnalyze: (type: ObservationType, text: string) => void;
}) {
  const [type, setType] = useState<ObservationType>("log");
  const [text, setText] = useState("");

  return (
    <section className="flex flex-col overflow-hidden rounded-xl border border-[#1e1e5a] bg-[#141432]">
      <div className="flex items-center justify-between border-b border-[#1e1e5a] bg-[#1e1e5a]/20 p-4">
        <h2 className="font-mono-display text-xs font-bold uppercase tracking-widest text-white">
          Observation Entry
        </h2>
        <span className="text-[10px] text-slate-500">ID: 0xFD29</span>
      </div>

      <div className="flex-1 space-y-5 overflow-y-auto p-6">
        <div>
          <label className="font-mono-display mb-2 block text-[11px] uppercase tracking-wider text-slate-400">
            Source Type
          </label>
          <select
            value={type}
            onChange={(e) => setType(e.target.value as ObservationType)}
            className="w-full cursor-pointer appearance-none rounded-lg border border-[#1e1e5a] bg-[#0a0a1a] px-4 py-3 text-sm text-slate-200 focus:border-[#4f46e5] focus:outline-none"
          >
            {TYPE_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="font-mono-display mb-2 block text-[11px] uppercase tracking-wider text-slate-400">
            Payload Content
          </label>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Paste synthetic logs, Nmap strings, or incident notes here..."
            maxLength={20000}
            className="font-mono-display h-64 w-full resize-none rounded-lg border border-[#1e1e5a] bg-[#0a0a1a] p-4 text-sm text-indigo-100 placeholder:text-slate-700 focus:border-[#4f46e5] focus:outline-none"
          />
          <div className="mt-2 flex items-center justify-between">
            <span className="text-[10px] text-slate-600">
              BYTES: {text.length} / 20000
            </span>
            <span className="text-[10px] uppercase tracking-tighter text-slate-600">
              UTF-8 Encoded
            </span>
          </div>
        </div>

        <div>
          <span className="font-mono-display mb-3 block text-[11px] uppercase tracking-wider text-slate-400">
            Synthetic Samples
          </span>
          <div className="flex flex-wrap gap-2">
            {SAMPLES.map((s) => (
              <button
                key={s.label}
                type="button"
                onClick={() => {
                  setType(s.type);
                  setText(s.text);
                }}
                className="rounded border border-[#1e1e5a] bg-[#1e1e5a]/40 px-3 py-1.5 text-[11px] text-slate-300 transition-colors hover:border-[#4f46e5] hover:text-white"
              >
                {s.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="border-t border-[#1e1e5a] p-6">
        <button
          onClick={() => onAnalyze(type, text.trim())}
          disabled={loading || text.trim().length < 5}
          className="font-mono-display flex w-full items-center justify-center gap-3 rounded-lg bg-[#4f46e5] py-4 text-sm font-bold uppercase tracking-widest text-white shadow-[0_0_20px_rgba(79,70,229,0.3)] transition-all hover:bg-[#4338ca] disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none"
        >
          {loading ? (
            <>
              <Loader2 className="h-5 w-5 animate-spin" /> Analyzing...
            </>
          ) : (
            <>
              <Play className="h-5 w-5" /> Begin Analysis
            </>
          )}
        </button>
      </div>
    </section>
  );
}
