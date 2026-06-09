"""Gradio entrypoint for ATT&CKLens."""

from __future__ import annotations

import os

import gradio as gr

from src.core import analyse_input, format_analysis


def analyze_for_ui(evidence: str) -> tuple[str, dict[str, object]]:
    """Return both readable Markdown and the structured JSON result."""

    result = analyse_input(evidence)
    return format_analysis(result), result


def build_app() -> gr.Blocks:
    with gr.Blocks(title="ATT&CKLens") as demo:
        gr.Markdown("# ATT&CKLens")
        gr.Markdown("Map synthetic defensive security observations to ATT&CK-style insights.")
        with gr.Row():
            evidence = gr.Textbox(
                label="Security observation",
                lines=10,
                placeholder="Paste a synthetic log snippet, alert summary, scan summary, or incident note.",
            )
        analyze_button = gr.Button("Analyze", variant="primary")
        readable_output = gr.Markdown(label="Analysis")
        json_output = gr.JSON(label="Structured output")
        analyze_button.click(
            analyze_for_ui,
            inputs=evidence,
            outputs=[readable_output, json_output],
        )
    return demo


if __name__ == "__main__":
    demo = build_app()
    demo.launch(
        server_name=os.getenv("GRADIO_SERVER_NAME", "127.0.0.1"),
        server_port=int(os.getenv("GRADIO_SERVER_PORT", "7860")),
        prevent_thread_lock=True,
    )
    demo.block_thread()
