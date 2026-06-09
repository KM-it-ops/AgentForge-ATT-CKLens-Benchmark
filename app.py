"""
ATT&CKLens - MITRE ATT&CK Mapping Tool

A defensive cybersecurity helper that maps sample security observations
to MITRE ATT&CK tactics and techniques.
"""

import gradio as gr
from src.core import analyse_input
import json


def format_output(result: dict) -> str:
    """Format the analysis result for human-readable display."""
    lines = []
    lines.append("## ATT&CKLens Analysis Results")
    lines.append("")
    
    # Summary
    lines.append(f"**Summary:** {result.get('summary', 'N/A')}")
    lines.append("")
    
    # Tactic and Technique
    tactic = result.get('tactic')
    technique_id = result.get('technique_id')
    
    if tactic and technique_id:
        lines.append(f"**Tactic:** {tactic}")
        lines.append(f"**Technique ID:** {technique_id}")
    else:
        lines.append("**Tactic:** Not determined")
        lines.append("**Technique ID:** Not determined")
    lines.append("")
    
    # Confidence
    confidence = result.get('confidence', 'low')
    lines.append(f"**Confidence:** {confidence}")
    lines.append("")
    
    # Evidence
    evidence = result.get('evidence', [])
    if evidence:
        lines.append("**Evidence:**")
        for i, frag in enumerate(evidence, 1):
            lines.append(f"  {i}. `{frag}`")
        lines.append("")
    else:
        lines.append("**Evidence:** None found")
        lines.append("")
    
    # Why Not
    why_not = result.get('why_not')
    if why_not:
        lines.append(f"**Why Not:** {why_not}")
        lines.append("")
    
    # Detection Idea
    detection_idea = result.get('detection_idea')
    if detection_idea:
        lines.append(f"**Detection Idea:** {detection_idea}")
        lines.append("")
    else:
        lines.append("**Detection Idea:** Not applicable")
        lines.append("")
    
    # Network Investigation
    network_inv = result.get('network_investigation')
    if network_inv:
        lines.append(f"**Network Investigation:** {network_inv}")
        lines.append("")
    else:
        lines.append("**Network Investigation:** Not applicable")
        lines.append("")
    
    # Remediation
    remediation = result.get('remediation')
    if remediation:
        lines.append(f"**Remediation:** {remediation}")
        lines.append("")
    
    # Analyst Questions
    questions = result.get('analyst_questions', [])
    if questions:
        lines.append("**Analyst Questions:**")
        for i, q in enumerate(questions, 1):
            lines.append(f"  {i}. {q}")
        lines.append("")
    
    # JSON Output
    lines.append("### Raw JSON Output:")
    lines.append("```json")
    lines.append(json.dumps(result, indent=2))
    lines.append("```")
    
    return "\n".join(lines)


def analyse_evidence(evidence: str) -> str:
    """Analyse the provided evidence and return formatted results."""
    try:
        result = analyse_input(evidence)
        return format_output(result)
    except Exception as e:
        return f"## Error\n\nAn error occurred during analysis: {str(e)}"


def main():
    """Launch the Gradio interface."""
    with gr.Blocks(
        title="ATT&CKLens - MITRE ATT&CK Mapping Tool"
    ) as demo:
        # Header
        gr.Markdown("# ATT&CKLens - MITRE ATT&CK Mapping Tool")
        gr.Markdown("""
        A defensive cybersecurity helper that maps sample security observations to MITRE ATT&CK tactics and techniques.
        
        **Instructions:**
        - Enter a security observation (log snippet, alert text, scan summary, etc.)
        - Click "Analyze" to get the ATT&CK mapping
        - Review the results and recommendations
        
        **Note:** This tool is for educational use in controlled lab environments only.
        """)
        
        # Input
        with gr.Row():
            evidence_input = gr.Textbox(
                label="Security Observation",
                placeholder="Enter security observation here...\n\nExamples:\n- Failed SSH login from 10.0.0.5 for user root\n- Repeated DNS requests to suspicious-domain.com every minute from 192.168.1.42\n- User reported that the system seemed slow yesterday.",
                lines=6,
                max_lines=10
            )
        
        # Submit button
        submit_btn = gr.Button("Analyze", variant="primary")
        
        # Output
        output_md = gr.Markdown(label="Analysis Results")
        
        # Examples
        gr.Markdown("""
        ### Example Inputs to Try:
        - `Failed SSH login from 10.0.0.5 for user root`
        - `Repeated DNS requests to suspicious-domain.com every minute from 192.168.1.42`
        - `User reported that the system seemed slow yesterday.`
        - `Process injection detected in lsass.exe`
        - `Multiple failed login attempts for admin account`
        """)
        
        # Connect the function
        submit_btn.click(
            fn=analyse_evidence,
            inputs=evidence_input,
            outputs=output_md
        )
        
        # Footer
        gr.Markdown("""
        ---
        **Disclaimer:** This tool is for educational and defensive purposes only. 
        Use only in authorized environments with synthetic or anonymized data.
        """)
    
    demo.launch()


if __name__ == "__main__":
    main()
