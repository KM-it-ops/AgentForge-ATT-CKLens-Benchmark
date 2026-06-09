import { AlertTriangle } from "lucide-react";

export function SafetyNote() {
  return (
    <div className="flex items-start gap-4 rounded-lg border border-amber-900/40 bg-amber-900/10 p-4">
      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-500" />
      <p className="text-xs leading-relaxed text-amber-200/80">
        This tool is for educational, defensive, and authorized lab use only. Use synthetic
        data &mdash; never paste real production credentials, PII, or unauthorized network
        captures.
      </p>
    </div>
  );
}
