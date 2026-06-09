import type { AnalysisResult } from "@/lib/analyze.functions";
import { Copy, AlertTriangle } from "lucide-react";
import { toast } from "sonner";

function Section({
  title,
  children,
  copyText,
}: {
  title: string;
  children: React.ReactNode;
  copyText?: string;
}) {
  return (
    <div className="rounded-xl border border-[#1e1e5a] bg-[#141432]">
      <div className="flex items-center justify-between border-b border-[#1e1e5a] bg-[#1e1e5a]/20 px-4 py-2.5">
        <h3 className="font-mono-display text-[11px] font-bold uppercase tracking-widest text-slate-300">
          {title}
        </h3>
        {copyText && (
          <button
            onClick={() => {
              navigator.clipboard.writeText(copyText);
              toast.success("Copied");
            }}
            className="text-slate-500 transition-colors hover:text-[#4f46e5]"
            aria-label="Copy section"
          >
            <Copy className="h-3.5 w-3.5" />
          </button>
        )}
      </div>
      <div className="p-4 text-sm leading-relaxed text-slate-300">{children}</div>
    </div>
  );
}

function confidenceClasses(c: "low" | "medium" | "high") {
  if (c === "high")
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-300";
  if (c === "medium") return "border-[#4f46e5]/40 bg-[#4f46e5]/10 text-indigo-300";
  return "border-amber-500/30 bg-amber-500/10 text-amber-300";
}

function toMarkdown(r: AnalysisResult): string {
  const lines: string[] = [];
  lines.push(`# ATT&CKLens Analysis`);
  lines.push(`\n## Summary\n${r.summary}`);
  lines.push(`\n## MITRE Mapping`);
  if (r.mapping === "mapped") {
    lines.push(`- Tactic: ${r.tactic ?? "—"}`);
    lines.push(`- Technique: ${r.techniqueId ?? "—"} ${r.techniqueName ?? ""}`);
  } else {
    lines.push(`No clear MITRE mapping.`);
  }
  lines.push(`\n## Confidence\n${r.confidence}`);
  lines.push(`\n## Evidence`);
  r.evidence.forEach((e) => lines.push(`- "${e}"`));
  lines.push(`\n## Why this mapping might be wrong\n${r.uncertainty}`);
  lines.push(`\n## Splunk-style detection idea\n\`\`\`\n${r.detectionIdea}\n\`\`\``);
  if (r.networkAngle)
    lines.push(`\n## Wireshark / network investigation\n${r.networkAngle}`);
  lines.push(`\n## Remediation`);
  r.remediation.forEach((s) => lines.push(`- ${s}`));
  lines.push(`\n## Analyst follow-up questions`);
  r.followUpQuestions.forEach((q) => lines.push(`- ${q}`));
  return lines.join("\n");
}

export function AnalysisResultView({ result }: { result: AnalysisResult }) {
  const md = toMarkdown(result);
  const mapped = result.mapping === "mapped";

  return (
    <div className="space-y-4">
      {/* Verdict header */}
      <div className="rounded-xl border border-[#1e1e5a] bg-[#141432] p-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {mapped ? (
              <>
                <span className="font-mono-display rounded border border-[#4f46e5]/40 bg-[#4f46e5]/10 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-indigo-300">
                  {result.tactic ?? "Tactic"}
                </span>
                <span className="font-mono-display rounded bg-[#4f46e5] px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-white shadow-[0_0_12px_rgba(79,70,229,0.4)]">
                  {result.techniqueId} {result.techniqueName}
                </span>
              </>
            ) : (
              <span className="font-mono-display flex items-center gap-1.5 rounded border border-amber-500/40 bg-amber-500/10 px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider text-amber-300">
                <AlertTriangle className="h-3 w-3" />
                No clear MITRE mapping
              </span>
            )}
            <span
              className={`font-mono-display rounded border px-2.5 py-1 text-[11px] font-bold uppercase tracking-wider ${confidenceClasses(
                result.confidence,
              )}`}
            >
              Confidence: {result.confidence}
            </span>
          </div>
          <button
            onClick={() => {
              navigator.clipboard.writeText(md);
              toast.success("Full report copied as Markdown");
            }}
            className="font-mono-display flex items-center gap-2 rounded border border-[#1e1e5a] bg-[#1e1e5a]/40 px-3 py-1.5 text-[11px] uppercase tracking-wider text-slate-300 transition-colors hover:border-[#4f46e5] hover:text-white"
          >
            <Copy className="h-3 w-3" /> Copy Report
          </button>
        </div>
      </div>

      <Section title="Summary" copyText={result.summary}>
        {result.summary}
      </Section>

      <Section title="Evidence (quoted from input)">
        {result.evidence.length === 0 ? (
          <p className="text-slate-500">No direct quotes returned.</p>
        ) : (
          <ul className="space-y-2">
            {result.evidence.map((e, i) => (
              <li
                key={i}
                className="font-mono-display rounded border-l-2 border-[#4f46e5] bg-[#0a0a1a] px-3 py-2 text-xs text-indigo-100"
              >
                "{e}"
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section title="Why this mapping might be wrong" copyText={result.uncertainty}>
        {result.uncertainty}
      </Section>

      <Section title="Splunk-style detection idea" copyText={result.detectionIdea}>
        <pre className="font-mono-display overflow-x-auto rounded-lg border border-[#1e1e5a] bg-[#0a0a1a] p-3 text-xs leading-relaxed text-emerald-300">
{result.detectionIdea}
        </pre>
      </Section>

      {result.networkAngle && (
        <Section title="Wireshark / network investigation" copyText={result.networkAngle}>
          <p className="whitespace-pre-wrap">{result.networkAngle}</p>
        </Section>
      )}

      <Section title="Remediation">
        <ul className="space-y-1.5">
          {result.remediation.map((r, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-[#4f46e5]">›</span>
              <span>{r}</span>
            </li>
          ))}
        </ul>
      </Section>

      <Section title="Analyst follow-up questions">
        <ul className="space-y-1.5">
          {result.followUpQuestions.map((q, i) => (
            <li key={i} className="flex gap-2">
              <span className="text-[#4f46e5]">?</span>
              <span>{q}</span>
            </li>
          ))}
        </ul>
      </Section>
    </div>
  );
}
