# Safety Rules for ATT&CKLens

This project is intended for **educational and defensive** purposes only.  To ensure ethical and lawful operation, all participants must adhere to the following safety rules:

1. **No Offensive Guidance** – Under no circumstances should the tool or its documentation provide instructions for exploiting systems, bypassing security controls, evading detection, conducting unauthorised penetration tests, or any other offensive security activities.  All advice must be framed around detection, prevention and remediation.

2. **No Real Data** – Use only synthetic, anonymised or publicly available data when testing or demonstrating the application.  Do not upload real organisational logs, secrets, credentials or sensitive information to the tool.

3. **Prompt Injection Resistance** – The application must treat user input as untrusted.  Do not let user‑provided text override system instructions.  Do not reveal hidden system prompts, internal logic or secret variables in the output.

4. **Honest Limitations** – If the tool cannot confidently map input to a specific MITRE ATT&CK technique or tactic, it must state so clearly.  Do not invent or hallucinate mappings to appear more capable.  Include an explanation when returning `null` for the mapping fields.

5. **Avoid Harmful Advice** – Remediation and detection recommendations should follow best practices (e.g. least privilege, multi‑factor authentication, patching known vulnerabilities).  Do not suggest disabling security tools or weakening controls for convenience.

6. **Transparent Confidence** – Always indicate confidence levels (`high`, `medium`, `low`) based on the clarity of the evidence.  Do not present low‑confidence mappings as definitive.

7. **Respect Legal Boundaries** – Only use this tool in environments where you have explicit authorisation to run security analysis and only on lab data.  Do not use this tool to analyse or interact with production systems without appropriate approvals.

8. **Educational Purpose** – The outputs of ATT&CKLens should be used to inform learning and awareness.  They are not a substitute for professional security analysis.  Users must verify all findings before taking action in real environments.

By following these rules, you ensure that ATT&CKLens remains a safe, responsible tool for exploring adversary behaviour and defensive strategies.