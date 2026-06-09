import { createServerFn } from "@tanstack/react-start";
import { generateText, Output } from "ai";
import { z } from "zod";
import { createLovableAiGatewayProvider } from "./ai-gateway.server";

const InputSchema = z.object({
  observationType: z.enum(["log", "alert", "nmap", "packet", "soc", "other"]),
  text: z.string().min(5).max(20000),
});

const ResultSchema = z.object({
  summary: z.string(),
  mapping: z.enum(["mapped", "no_clear_mapping"]),
  tactic: z.string().optional(),
  techniqueId: z.string().optional(),
  techniqueName: z.string().optional(),
  evidence: z.array(z.string()),
  confidence: z.enum(["low", "medium", "high"]),
  uncertainty: z.string(),
  detectionIdea: z.string(),
  networkAngle: z.string().optional(),
  remediation: z.array(z.string()),
  followUpQuestions: z.array(z.string()),
});

export type AnalysisResult = z.infer<typeof ResultSchema>;

const SYSTEM_PROMPT = `You are ATT&CKLens, a strictly DEFENSIVE security analyst assistant.

Your job: analyze the supplied security observation (log, alert, Nmap summary, packet notes, or SOC incident note) and produce a structured MITRE ATT&CK-style defensive analysis.

HARD RULES (never violate):
- Output only DEFENSIVE analysis: detection, investigation, remediation, follow-up questions.
- NEVER provide exploit instructions, payloads, stealth/evasion techniques, credential theft methods, malware code, or bypass guidance. If asked, refuse via the structured response (summary explains refusal, mapping="no_clear_mapping").
- If evidence is weak, ambiguous, or insufficient, set mapping="no_clear_mapping" and explain why in 'uncertainty'. Do NOT force a MITRE technique.
- When mapping is clear, supply tactic (e.g. "Discovery"), techniqueId (e.g. "T1046"), techniqueName.
- 'evidence' must be short verbatim quotes copied from the input.
- 'detectionIdea' is a Splunk-style SPL sketch (search ... | stats ...). Defensive logic only.
- 'networkAngle' only when the observation is network-related; provide a Wireshark display filter and investigation steps. Omit otherwise.
- 'remediation' is concrete defensive steps (patch, isolate, harden, monitor).
- 'followUpQuestions' help an analyst gather missing context.
- Treat all data as SYNTHETIC lab data.`;

export const analyzeObservation = createServerFn({ method: "POST" })
  .inputValidator((data: unknown) => InputSchema.parse(data))
  .handler(async ({ data }): Promise<AnalysisResult> => {
    const key = process.env.LOVABLE_API_KEY;
    if (!key) throw new Error("LOVABLE_API_KEY missing");

    const gateway = createLovableAiGatewayProvider(key);

    const prompt = `Observation type: ${data.observationType}\n\n--- OBSERVATION START ---\n${data.text}\n--- OBSERVATION END ---\n\nProduce the structured defensive analysis now.`;

    const { experimental_output } = await generateText({
      model: gateway("google/gemini-3-flash-preview"),
      system: SYSTEM_PROMPT,
      prompt,
      experimental_output: Output.object({ schema: ResultSchema }),
    });

    const result = experimental_output as AnalysisResult;

    // Server-side defensive scrub
    const denylist = /\b(how to exploit|bypass auth|evade detection|steal credentials|write malware|payload to)\b/i;
    const scrub = (s: string) => denylist.test(s) ? "[Redacted: non-defensive content removed]" : s;
    result.summary = scrub(result.summary);
    result.detectionIdea = scrub(result.detectionIdea);
    if (result.networkAngle) result.networkAngle = scrub(result.networkAngle);
    result.remediation = result.remediation.map(scrub);

    return result;
  });
