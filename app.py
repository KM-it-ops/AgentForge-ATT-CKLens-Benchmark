"""ATT&CKLens Gradio entry point."""

from __future__ import annotations

import gradio as gr

from src.core import analyse_input, format_result


def run_analysis(evidence: str) -> str:
    result = analyse_input(evidence)
    return format_result(result)


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="ATT&CKLens") as demo:
        gr.Markdown(
            "# ATT&CKLens\n"
            "Map sample security observations to MITRE ATT&CK tactics and techniques. "
            "**Defensive / educational use only.** Paste one observation at a time."
        )
        evidence = gr.Textbox(
            label="Security observation",
            placeholder="Paste a log snippet, alert summary, scan note, or short narrative…",
            lines=8,
        )
        submit = gr.Button("Analyse", variant="primary")
        output = gr.Textbox(label="Analysis", lines=24, max_lines=40)

        submit.click(fn=run_analysis, inputs=evidence, outputs=output)
        evidence.submit(fn=run_analysis, inputs=evidence, outputs=output)

    return demo


if __name__ == "__main__":
    build_ui().launch()
