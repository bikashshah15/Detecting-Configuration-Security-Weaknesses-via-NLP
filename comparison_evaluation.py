import csv
import json
from typing import Dict, List, Tuple

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

GROUND_TRUTH_CSV = "k8s_labels.csv"
RULE_BASED_JSON = "consolidated_report.json"
NLP_PREDICTIONS_CSV = "tfidf_test_predictions.csv"

OUT_METRICS_JSON = "hybrid_metrics.json"
OUT_PREDICTIONS_CSV = "hybrid_predictions.csv"
OUT_MISMATCHES_CSV = "hybrid_mismatches.csv"

NLP_MODEL_NAME = "linear_svm"


def load_ground_truth(csv_path: str) -> Dict[str, str]:
    df = pd.read_csv(csv_path)

    required = {"file_name", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in {csv_path}: {sorted(missing)}")

    return {
        str(row["file_name"]).strip(): str(row["label"]).strip()
        for _, row in df.iterrows()
        if str(row["file_name"]).strip()
    }


def load_rule_predictions(json_path: str) -> Dict[str, Dict]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"{json_path} must contain a top-level JSON object.")

    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ValueError(f"{json_path} must contain a 'findings' list.")

    rule_map = {}
    for item in findings:
        if not isinstance(item, dict):
            continue

        file_name = str(item.get("file_name", "")).strip()
        if not file_name:
            continue

        rule_map[file_name] = {
            "rule_pred": str(item.get("final_label", "")).strip(),
            "final_severity": str(item.get("final_severity", "")).strip(),
            "label_from_structural": str(item.get("label_from_structural", "")).strip(),
            "label_from_regex": str(item.get("label_from_regex", "")).strip(),
            "parse_error": "" if item.get("parse_error") is None else str(item.get("parse_error")),
        }

    return rule_map


def load_nlp_predictions(csv_path: str, model_name: str) -> Dict[str, Dict]:
    df = pd.read_csv(csv_path)

    required = {"file_name", "true_label", "predicted_label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in {csv_path}: {sorted(missing)}")

    if "model" in df.columns:
        df = df[df["model"] == model_name].copy()

    if df.empty:
        raise ValueError(
            f"No rows found for model '{model_name}' in {csv_path}. "
            f"Check the model column values."
        )

    return {
        str(row["file_name"]).strip(): {
            "true_label_from_nlp_file": str(row["true_label"]).strip(),
            "nlp_pred": str(row["predicted_label"]).strip(),
            "nlp_correct": bool(row["correct"]) if "correct" in df.columns else None,
        }
        for _, row in df.iterrows()
        if str(row["file_name"]).strip()
    }


def build_combined_dataframe(
    ground_truth: Dict[str, str],
    rule_preds: Dict[str, Dict],
    nlp_preds: Dict[str, Dict],
) -> pd.DataFrame:
    rows = []

    all_files = sorted(set(ground_truth.keys()) | set(rule_preds.keys()) | set(nlp_preds.keys()))

    for file_name in all_files:
        true_label = ground_truth.get(file_name, "")
        rule_info = rule_preds.get(file_name, {})
        nlp_info = nlp_preds.get(file_name, {})

        rows.append({
            "file_name": file_name,
            "true_label": true_label,
            "rule_pred": rule_info.get("rule_pred", ""),
            "nlp_pred": nlp_info.get("nlp_pred", ""),
            "final_severity": rule_info.get("final_severity", ""),
            "label_from_structural": rule_info.get("label_from_structural", ""),
            "label_from_regex": rule_info.get("label_from_regex", ""),
            "parse_error": rule_info.get("parse_error", ""),
        })

    df = pd.DataFrame(rows)

    # Keep only files that have all three: ground truth, rule prediction, nlp prediction
    df = df[
        (df["true_label"] != "") &
        (df["rule_pred"] != "") &
        (df["nlp_pred"] != "")
    ].copy()

    if df.empty:
        raise ValueError("No overlapping files found across ground truth, rule predictions, and NLP predictions.")

    return df


def apply_hybrid_predictions(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Hybrid 1: Rule-first
    # If rule says insecure, trust it. Otherwise use NLP.
    df["hybrid_rule_first"] = df.apply(
        lambda row: row["rule_pred"] if row["rule_pred"] != "secure" else row["nlp_pred"],
        axis=1,
    )

    # Hybrid 2: Privilege override
    # Explicit privilege issues are trusted from rules, everything else from NLP.
    df["hybrid_privilege_override"] = df.apply(
        lambda row: "privilege_exposure" if row["rule_pred"] == "privilege_exposure" else row["nlp_pred"],
        axis=1,
    )

    return df


def evaluate_predictions(y_true: List[str], y_pred: List[str]) -> Dict:
    labels = sorted(set(y_true) | set(y_pred))

    accuracy = accuracy_score(y_true, y_pred)

    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, average="weighted", zero_division=0
    )

    per_class = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_true, y_pred, labels=labels)

    return {
        "accuracy": round(float(accuracy), 4),
        "macro_precision": round(float(precision_macro), 4),
        "macro_recall": round(float(recall_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_precision": round(float(precision_weighted), 4),
        "weighted_recall": round(float(recall_weighted), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "labels": labels,
        "confusion_matrix": cm.tolist(),
        "classification_report": per_class,
    }


def build_mismatches(df: pd.DataFrame, pred_col: str, method_name: str) -> pd.DataFrame:
    out = df[df[pred_col] != df["true_label"]].copy()
    out["method"] = method_name
    out["predicted_label"] = out[pred_col]
    return out[
        [
            "method",
            "file_name",
            "true_label",
            "predicted_label",
            "rule_pred",
            "nlp_pred",
            "final_severity",
            "label_from_structural",
            "label_from_regex",
            "parse_error",
        ]
    ].copy()


def main() -> None:
    ground_truth = load_ground_truth(GROUND_TRUTH_CSV)
    rule_preds = load_rule_predictions(RULE_BASED_JSON)
    nlp_preds = load_nlp_predictions(NLP_PREDICTIONS_CSV, NLP_MODEL_NAME)

    df = build_combined_dataframe(ground_truth, rule_preds, nlp_preds)
    df = apply_hybrid_predictions(df)

    y_true = df["true_label"].tolist()

    results = {
        "dataset": {
            "num_aligned_files": int(len(df)),
            "nlp_model_used": NLP_MODEL_NAME,
        },
        "models": {
            "rule_based": evaluate_predictions(y_true, df["rule_pred"].tolist()),
            "nlp": evaluate_predictions(y_true, df["nlp_pred"].tolist()),
            "hybrid_rule_first": evaluate_predictions(y_true, df["hybrid_rule_first"].tolist()),
            "hybrid_privilege_override": evaluate_predictions(y_true, df["hybrid_privilege_override"].tolist()),
        },
    }

    comparison_summary = {}
    for model_name, metrics in results["models"].items():
        comparison_summary[model_name] = {
            "accuracy": metrics["accuracy"],
            "macro_f1": metrics["macro_f1"],
            "weighted_f1": metrics["weighted_f1"],
        }

    results["comparison_summary"] = comparison_summary

    # Save merged predictions
    df.to_csv(OUT_PREDICTIONS_CSV, index=False)

    # Save mismatches for all methods together
    mismatch_frames = [
        build_mismatches(df, "rule_pred", "rule_based"),
        build_mismatches(df, "nlp_pred", "nlp"),
        build_mismatches(df, "hybrid_rule_first", "hybrid_rule_first"),
        build_mismatches(df, "hybrid_privilege_override", "hybrid_privilege_override"),
    ]
    mismatches_df = pd.concat(mismatch_frames, ignore_index=True)
    mismatches_df.to_csv(OUT_MISMATCHES_CSV, index=False)

    # Save metrics JSON
    with open(OUT_METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print(f"Saved hybrid metrics to {OUT_METRICS_JSON}")
    print(f"Saved hybrid predictions to {OUT_PREDICTIONS_CSV}")
    print(f"Saved hybrid mismatches to {OUT_MISMATCHES_CSV}")

    print("\nComparison summary:")
    for model_name, summary in comparison_summary.items():
        print(
            f"  {model_name}: "
            f"accuracy={summary['accuracy']}, "
            f"macro_f1={summary['macro_f1']}, "
            f"weighted_f1={summary['weighted_f1']}"
        )


if __name__ == "__main__":
    main()