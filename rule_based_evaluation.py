import csv
import json
from typing import Dict, List, Tuple

GROUND_TRUTH_CSV = "k8s_labels.csv"
RULE_BASED_JSON = "consolidated_report.json"

OUT_METRICS_JSON = "rule_based_metrics.json"
OUT_MISMATCHES_CSV = "rule_based_mismatches.csv"


def load_ground_truth(csv_path: str) -> Dict[str, str]:
    truth = {}

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)

        required_cols = {"file_name", "label"}
        missing = required_cols - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing required columns in {csv_path}: {sorted(missing)}")

        for row in reader:
            file_name = (row.get("file_name") or "").strip()
            label = (row.get("label") or "").strip()

            if file_name:
                truth[file_name] = label

    return truth


def load_predictions(json_path: str) -> Tuple[Dict[str, str], Dict[str, dict], dict]:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError(f"{json_path} must contain a top-level JSON object.")

    findings = data.get("findings")
    summary = data.get("summary", {})

    if not isinstance(findings, list):
        raise ValueError(f"{json_path} must contain a 'findings' list.")

    preds = {}
    full_items = {}

    for item in findings:
        if not isinstance(item, dict):
            continue

        file_name = str(item.get("file_name", "")).strip()
        predicted_label = str(item.get("final_label", "")).strip()

        if not file_name:
            continue

        preds[file_name] = predicted_label
        full_items[file_name] = item

    return preds, full_items, summary


def safe_divide(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator != 0 else 0.0


def compute_confusion_matrix(
    y_true: List[str],
    y_pred: List[str],
    labels: List[str],
) -> Dict[str, Dict[str, int]]:
    matrix = {true_label: {pred_label: 0 for pred_label in labels} for true_label in labels}

    for t, p in zip(y_true, y_pred):
        if t not in matrix:
            matrix[t] = {pred_label: 0 for pred_label in labels}
        if p not in matrix[t]:
            for row_label in matrix:
                if p not in matrix[row_label]:
                    matrix[row_label][p] = 0
        matrix[t][p] += 1

    return matrix


def compute_per_class_metrics(
    confusion: Dict[str, Dict[str, int]],
    labels: List[str],
) -> Dict[str, Dict[str, float]]:
    metrics = {}

    for label in labels:
        tp = confusion.get(label, {}).get(label, 0)

        fp = sum(
            confusion.get(true_label, {}).get(label, 0)
            for true_label in labels
            if true_label != label
        )

        fn = sum(
            confusion.get(label, {}).get(pred_label, 0)
            for pred_label in labels
            if pred_label != label
        )

        support = sum(confusion.get(label, {}).values())

        precision = safe_divide(tp, tp + fp)
        recall = safe_divide(tp, tp + fn)
        f1 = safe_divide(2 * precision * recall, precision + recall) if (precision + recall) > 0 else 0.0

        metrics[label] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }

    return metrics


def compute_overall_accuracy(y_true: List[str], y_pred: List[str]) -> float:
    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    return round(safe_divide(correct, len(y_true)), 4)


def compute_macro_average(per_class_metrics: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    labels = list(per_class_metrics.keys())
    if not labels:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    return {
        "precision": round(sum(per_class_metrics[l]["precision"] for l in labels) / len(labels), 4),
        "recall": round(sum(per_class_metrics[l]["recall"] for l in labels) / len(labels), 4),
        "f1": round(sum(per_class_metrics[l]["f1"] for l in labels) / len(labels), 4),
    }


def compute_weighted_average(per_class_metrics: Dict[str, Dict[str, float]]) -> Dict[str, float]:
    total_support = sum(m["support"] for m in per_class_metrics.values())
    if total_support == 0:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    return {
        "precision": round(sum(m["precision"] * m["support"] for m in per_class_metrics.values()) / total_support, 4),
        "recall": round(sum(m["recall"] * m["support"] for m in per_class_metrics.values()) / total_support, 4),
        "f1": round(sum(m["f1"] * m["support"] for m in per_class_metrics.values()) / total_support, 4),
    }


def collect_alignment(
    ground_truth: Dict[str, str],
    predictions: Dict[str, str],
    full_items: Dict[str, dict],
) -> Tuple[List[str], List[str], List[Dict[str, str]]]:
    y_true = []
    y_pred = []
    mismatches = []

    for file_name, true_label in sorted(ground_truth.items()):
        if file_name not in predictions:
            mismatches.append({
                "file_name": file_name,
                "true_label": true_label,
                "predicted_label": "MISSING_PREDICTION",
                "status": "missing_prediction",
                "final_severity": "",
                "label_from_structural": "",
                "label_from_regex": "",
                "parse_error": "",
            })
            continue

        pred_label = predictions[file_name]
        y_true.append(true_label)
        y_pred.append(pred_label)

        if true_label != pred_label:
            item = full_items.get(file_name, {})
            mismatches.append({
                "file_name": file_name,
                "true_label": true_label,
                "predicted_label": pred_label,
                "status": "label_mismatch",
                "final_severity": str(item.get("final_severity", "")),
                "label_from_structural": str(item.get("label_from_structural", "")),
                "label_from_regex": str(item.get("label_from_regex", "")),
                "parse_error": str(item.get("parse_error", "")),
            })

    for file_name, pred_label in sorted(predictions.items()):
        if file_name not in ground_truth:
            item = full_items.get(file_name, {})
            mismatches.append({
                "file_name": file_name,
                "true_label": "MISSING_GROUND_TRUTH",
                "predicted_label": pred_label,
                "status": "missing_ground_truth",
                "final_severity": str(item.get("final_severity", "")),
                "label_from_structural": str(item.get("label_from_structural", "")),
                "label_from_regex": str(item.get("label_from_regex", "")),
                "parse_error": str(item.get("parse_error", "")),
            })

    return y_true, y_pred, mismatches


def save_mismatches_csv(path: str, mismatches: List[Dict[str, str]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "file_name",
                "true_label",
                "predicted_label",
                "status",
                "final_severity",
                "label_from_structural",
                "label_from_regex",
                "parse_error",
            ],
        )
        writer.writeheader()
        writer.writerows(mismatches)


def main() -> None:
    ground_truth = load_ground_truth(GROUND_TRUTH_CSV)
    predictions, full_items, report_summary = load_predictions(RULE_BASED_JSON)

    y_true, y_pred, mismatches = collect_alignment(ground_truth, predictions, full_items)

    if not y_true:
        raise ValueError("No overlapping files found between ground truth CSV and JSON report.")

    labels = sorted(set(y_true) | set(y_pred))
    confusion = compute_confusion_matrix(y_true, y_pred, labels)
    per_class_metrics = compute_per_class_metrics(confusion, labels)
    accuracy = compute_overall_accuracy(y_true, y_pred)
    macro_avg = compute_macro_average(per_class_metrics)
    weighted_avg = compute_weighted_average(per_class_metrics)

    metrics_report = {
        "input_report_summary": report_summary,
        "evaluation_summary": {
            "num_ground_truth_files": len(ground_truth),
            "num_prediction_files": len(predictions),
            "num_aligned_files": len(y_true),
            "num_label_mismatches": len([m for m in mismatches if m["status"] == "label_mismatch"]),
            "num_missing_predictions": len([m for m in mismatches if m["status"] == "missing_prediction"]),
            "num_missing_ground_truth": len([m for m in mismatches if m["status"] == "missing_ground_truth"]),
            "accuracy": accuracy,
        },
        "labels": labels,
        "per_class_metrics": per_class_metrics,
        "macro_avg": macro_avg,
        "weighted_avg": weighted_avg,
        "confusion_matrix": confusion,
    }

    with open(OUT_METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(metrics_report, f, indent=2)

    save_mismatches_csv(OUT_MISMATCHES_CSV, mismatches)

    print(f"Saved metrics to {OUT_METRICS_JSON}")
    print(f"Saved mismatches to {OUT_MISMATCHES_CSV}")
    print("\nEvaluation summary")
    print(f"Aligned files: {len(y_true)}")
    print(f"Accuracy: {accuracy}")
    print("Per-class metrics:")
    for label in labels:
        m = per_class_metrics[label]
        print(
            f"  {label}: precision={m['precision']}, recall={m['recall']}, "
            f"f1={m['f1']}, support={m['support']}"
        )


if __name__ == "__main__":
    main()