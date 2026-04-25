from __future__ import annotations

from typing import Any, Dict

from flask import Flask, render_template, request

from hybrid_detection_pipeline import analyze_yaml_content


app = Flask(__name__)


def empty_result() -> Dict[str, Any]:
    return {
        "file_name": "submitted.yaml",
        "submitted_yaml": "",
        "final_label": None,
        "final_severity": None,
        "label_from_structural": None,
        "label_from_nlp": None,
        "nlp_confidence": None,
        "nlp_note": None,
        "parse_error": None,
        "privilege_findings": [],
        "hardcoded_secret_findings": [],
        "safe_secret_references": [],
        "line_annotations": [],
        "highlighted_lines": [],
    }


@app.route("/", methods=["GET", "POST"])
def index():
    result = empty_result()
    error_message = None

    if request.method == "POST":
        yaml_text = (request.form.get("yaml_text") or "").strip()
        uploaded_file = request.files.get("yaml_file")
        source_name = "submitted.yaml"

        if uploaded_file and uploaded_file.filename:
            source_name = uploaded_file.filename
            uploaded_text = uploaded_file.read().decode("utf-8", errors="ignore")
            if uploaded_text.strip():
                yaml_text = uploaded_text

        if not yaml_text:
            error_message = "Provide a YAML file or paste YAML text before submitting."
        else:
            result = analyze_yaml_content(content=yaml_text, file_name=source_name)

    return render_template("index.html", result=result, error_message=error_message)


if __name__ == "__main__":
    app.run(debug=True)
