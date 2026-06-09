## ATT&CKLens — Defensive MITRE ATT&CK Analyzer

A single-page, no-login, no-DB web app that takes a security observation (logs, alerts, Nmap, packet notes, SOC notes) and returns structured defensive analysis from Lovable AI.

### Stack & scope
- TanStack Start + Tailwind, "Clean Analyst" palette (slate/blue/amber on near-white).
- Enable Lovable Cloud only for the `LOVABLE_API_KEY` secret needed by the AI Gateway. No DB, no auth, no tables.
- One server function `analyzeObservation` in `src/lib/analyze.functions.ts` calls Gemini via the AI SDK with a strict structured-output schema and a defensive-only system prompt.

### Routes / files
- `src/routes/index.tsx` — the whole app (input form + results panel).
- `src/lib/ai-gateway.server.ts` — Lovable AI Gateway provider helper.
- `src/lib/analyze.functions.ts` — `analyzeObservation` server function (Zod input + `Output.object` schema).
- `src/components/AnalysisInput.tsx` — textarea, observation-type selector (Log / Alert / Nmap / Packet notes / SOC note / Other), analyze button.
- `src/components/AnalysisResult.tsx` — renders all required sections as cards.
- `src/components/SafetyNote.tsx` — persistent banner: "This tool is for educational, defensive, and authorized lab use only."
- `src/components/SampleObservations.tsx` — 3–4 synthetic examples a user can load with one click.

### AI contract (structured output)
System prompt enforces defensive-only behavior: never produce exploit, evasion, credential theft, malware, or bypass guidance; if evidence is weak, set `mapping` to `"no_clear_mapping"` and explain why.

Response schema:
- `summary: string`
- `mapping: "mapped" | "no_clear_mapping"`
- `tactic?: string` (e.g. "Discovery")
- `techniqueId?: string` (e.g. "T1046")
- `techniqueName?: string`
- `evidence: string[]` (quoted spans from input)
- `confidence: "low" | "medium" | "high"`
- `uncertainty: string` (why this mapping might be wrong)
- `detectionIdea: string` (Splunk-style SPL sketch)
- `networkAngle?: string` (Wireshark filter / investigation steps; omitted if not network-related)
- `remediation: string[]`
- `followUpQuestions: string[]`

Server-side guard: if the model returns text matching a small denylist (e.g. "how to exploit", "bypass", "evade"), strip the field and replace with a safe placeholder.

### UI layout (Clean Analyst)
- Top bar: "ATT&CKLens" wordmark + tagline + safety banner.
- Left: input card (type selector, textarea, sample loader, Analyze button with loading state).
- Right: results panel with clearly separated sections (Summary, MITRE Mapping, Evidence, Confidence, Why this might be wrong, Splunk-style detection, Network / Wireshark angle, Remediation, Analyst follow-up questions). When `mapping === "no_clear_mapping"`, show an amber "No clear MITRE mapping" badge instead of tactic/technique.
- Empty state with instructions; error state for 429 (rate limit) and 402 (credits).
- Copy-to-clipboard on each section and "Copy full report (Markdown)".

### Safety / scope guardrails
- Safety note visible on every render.
- System prompt + UI hint forbid asking for offensive guidance; if the user input requests it, the model responds with a refusal that still fills `summary` + `followUpQuestions` and sets `mapping: "no_clear_mapping"`.
- Synthetic samples only; no real IPs / hostnames.

### Out of scope (hard constraints, per request)
No login, accounts, database, payments, or complex backend services. No offensive content.

### Verification
After build, send one sample (Nmap scan summary) through the form and confirm the response renders all sections and that an ambiguous input returns `no_clear_mapping`.
