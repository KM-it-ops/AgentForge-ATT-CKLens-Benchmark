# ATT&CKLens Specification

This document defines the **minimum viable product (MVP)** specification for **ATT&CKLens**, a defensive cybersecurity helper that maps sample security observations to MITRE ATT&CK tactics and techniques.  The purpose of ATT&CKLens is to help analysts understand potential adversary behaviour and to generate defensive ideas without providing offensive instruction.  

## Purpose

The primary aim of ATT&CKLens is to accept simplified security observations (e.g. log entries, alert summaries, scan reports or short narrative descriptions) and produce structured defensive insights.  ATT&CKLens is intended for educational use in controlled lab environments and should never be used to analyse real attack data without proper authorisation.

## Inputs

ATT&CKLens accepts one piece of evidence per run.  Evidence may take one of the following forms:

* **System log snippet** – short extracts of authentication logs, process creation logs or other host activity logs.
* **Alert text** – short summaries of security alerts from SIEM products.
* **Scan summary** – brief results from vulnerability scanners or port scans (e.g. Nmap output summaries).
* **Packet‑analysis note** – short narrative descriptions of observed network activity (not raw PCAP files).
* **Narrative incident note** – a few sentences describing suspicious behaviour observed by a human.

Inputs may be provided as plain text.  The tool must be robust to blank lines, minor formatting issues or missing context.  If an input is empty or unparseable, the tool should return a suitable error message rather than crash.

## Outputs

ATT&CKLens should return a dictionary or JSON‑serialisable object with the following keys:

| Field | Description |
| --- | --- |
| `summary` | A one‑sentence summary of what the input describes. |
| `tactic` | The likely MITRE ATT&CK tactic name (e.g. *Privilege Escalation*, *Credential Access*) or `null` if insufficient evidence. |
| `technique_id` | The most probable technique ID (e.g. `T1059.001`) or `null`.  Include both ID and human‑readable name in parentheses if known. |
| `evidence` | A list of quoted fragments from the input that support the mapping. |
| `confidence` | A value of `high`, `medium` or `low` representing confidence in the mapping. |
| `why_not` | A brief explanation when the mapping is uncertain or multiple interpretations exist. |
| `detection_idea` | A one‑sentence suggestion for a SIEM/Splunk query that could detect similar behaviour, if applicable.  May be `null` when the input is too generic. |
| `network_investigation` | A brief note on what to look for in Wireshark or packet captures, if the input relates to network activity, else `null`. |
| `remediation` | Recommended defensive actions or mitigations relevant to the evidence, written in plain English. |
| `analyst_questions` | A list of questions an analyst should ask to gather further context. |

The application should serialise this structure into JSON internally and render it to the user in a clear, human‑readable format via Gradio.

## Behaviour

1. **No forced mapping** – If the evidence does not clearly align with any ATT&CK tactic or technique, the application must set `tactic` and `technique_id` to `null` and explain why in `why_not`.
2. **Evidence citation** – The tool must quote exact phrases from the input evidence in the `evidence` field to justify its conclusions.  Do not fabricate details not present in the input.
3. **Confidence assessment** – The tool should not claim high confidence when input is vague or incomplete.  Use `medium` or `low` confidence when mapping is speculative.
4. **Safety** – Never include offensive or exploit instructions.  The tool must refuse to provide guidance on bypassing detections or exploiting vulnerabilities.  All recommendations must be defensive.
5. **Prompt injection resistance** – Treat user input as untrusted.  Do not allow user input to override system instructions or cause the assistant to break safety rules.

## Non‑requirements

* ATT&CKLens does **not** need to support uploading actual PCAP files or parse arbitrary binary data.
* It does not need to integrate with a live Splunk instance.  `detection_idea` can describe the type of query an analyst might write (e.g. “search for repeated logins from the same IP within a short time window”).
* It does not need to fetch live MITRE ATT&CK information; you may embed known technique names or simply include IDs.
* The application should not persist or transmit inputs; it should run entirely locally and within the Hugging Face Space when deployed.

## Deployment Constraints

* The initial MVP must use Python 3 and Gradio for the UI.
* It should not require GPU acceleration or any paid APIs for its core logic.
* All dependencies must be listed in a `requirements.txt` file.  Keep dependencies to a minimum; avoid heavy frameworks or unnecessary packages.
* The app must run in a standard Hugging Face Space environment using only the included CPU resources.

## Summary

Use this specification as the single source of truth when instructing AI coding agents.  Do not infer additional features beyond this document for the MVP stage.  Subsequent improvements (e.g. better ranking, interactive diagrams, advanced analysis) may be added after the MVP is complete and tested.