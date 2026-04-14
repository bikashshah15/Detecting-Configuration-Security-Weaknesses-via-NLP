import os
import json
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, cross_validate, StratifiedKFold
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

LABEL_CSV = "k8s_labels.csv"
YAML_DIR = "k8s_yaml_only"

OUT_METRICS_JSON = "tfidf_metrics.json"
OUT_TEST_PREDICTIONS_CSV = "tfidf_test_predictions.csv"
OUT_CONFUSION_JSON = "tfidf_confusion_matrix.json"

RANDOM_STATE = 42
TEST_SIZE = 0.20
CV_FOLDS = 5


def load_labeled_yaml_data(label_csv: str, yaml_dir: str) -> pd.DataFrame:
    df = pd.read_csv(label_csv)

    required_cols = {"file_name", "label"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in {label_csv}: {sorted(missing)}")

    records: List[Dict[str, str]] = []
    missing_files: List[str] = []

    for _, row in df.iterrows():
        file_name = str(row["file_name"]).strip()
        label = str(row["label"]).strip()

        file_path = os.path.join(yaml_dir, file_name)
        if not os.path.isfile(file_path):
            missing_files.append(file_name)
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

        records.append({
            "file_name": file_name,
            "label": label,
            "text": content,
        })

    if missing_files:
        print(f"Warning: {len(missing_files)} labeled files were missing from {yaml_dir} and were skipped.")

    if not records:
        raise ValueError("No usable labeled YAML files were loaded.")

    return pd.DataFrame(records)


def build_vectorizer() -> TfidfVectorizer:

    return TfidfVectorizer(
        lowercase=True,
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=50000,
        sublinear_tf=True,
    )


def build_models() -> Dict[str, object]:

    return {
        "logistic_regression": LogisticRegression(
            max_iter=2000,
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),
        "linear_svm": LinearSVC(
            class_weight="balanced",
            random_state=RANDOM_STATE,
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=RANDOM_STATE,
            n_jobs=-1,
        ),
    }


def build_pipeline(classifier: object) -> Pipeline:
    return Pipeline([
        ("tfidf", build_vectorizer()),
        ("clf", classifier),
    ])


def run_cross_validation_on_training(model: Pipeline, X_train: pd.Series, y_train: pd.Series) -> Dict:

    cv = StratifiedKFold(n_splits=CV_FOLDS, shuffle=True, random_state=RANDOM_STATE)

    scoring = {
        "accuracy": "accuracy",
        "precision_macro": "precision_macro",
        "recall_macro": "recall_macro",
        "f1_macro": "f1_macro",
        "precision_weighted": "precision_weighted",
        "recall_weighted": "recall_weighted",
        "f1_weighted": "f1_weighted",
    }

    cv_results = cross_validate(
        model,
        X_train,
        y_train,
        cv=cv,
        scoring=scoring,
        return_train_score=False,
        n_jobs=1,
    )

    summary = {}
    for metric_name, values in cv_results.items():
        if not metric_name.startswith("test_"):
            continue

        metric_key = metric_name.replace("test_", "")
        summary[metric_key] = {
            "mean": round(float(np.mean(values)), 4),
            "std": round(float(np.std(values)), 4),
            "fold_scores": [round(float(v), 4) for v in values],
        }

    return summary


def evaluate_test_set(
    model: Pipeline,
    X_test: pd.Series,
    y_test: pd.Series,
    file_names: pd.Series,
) -> Tuple[Dict, pd.DataFrame, Dict]:

    y_pred = model.predict(X_test)

    accuracy = accuracy_score(y_test, y_pred)

    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0
    )

    labels = sorted(list(set(y_test) | set(y_pred)))
    clf_report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=labels)

    metrics = {
        "accuracy": round(float(accuracy), 4),
        "macro_precision": round(float(precision_macro), 4),
        "macro_recall": round(float(recall_macro), 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_precision": round(float(precision_weighted), 4),
        "weighted_recall": round(float(recall_weighted), 4),
        "weighted_f1": round(float(f1_weighted), 4),
        "classification_report": clf_report,
    }

    predictions_df = pd.DataFrame({
        "file_name": file_names.values,
        "true_label": y_test.values,
        "predicted_label": y_pred,
        "correct": (y_test.values == y_pred),
    })

    confusion_payload = {
        "labels": labels,
        "matrix": cm.tolist(),
    }

    return metrics, predictions_df, confusion_payload


def save_confusion_by_model(confusion_results: Dict[str, Dict], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(confusion_results, f, indent=2)


def main() -> None:
    df = load_labeled_yaml_data(LABEL_CSV, YAML_DIR)

    print(f"Loaded {len(df)} labeled YAML files.")
    print("Full label distribution:")
    print(df["label"].value_counts())

    X = df["text"]
    y = df["label"]
    file_names = df["file_name"]

    X_train, X_test, y_train, y_test, f_train, f_test = train_test_split(
        X,
        y,
        file_names,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print(f"\nTrain size: {len(X_train)}")
    print(f"Test size: {len(X_test)}")
    print("\nTrain label distribution:")
    print(y_train.value_counts())
    print("\nTest label distribution:")
    print(y_test.value_counts())

    all_results: Dict[str, Dict] = {}
    all_test_predictions: List[pd.DataFrame] = []
    all_confusions: Dict[str, Dict] = {}

    for model_name, classifier in build_models().items():
        print(f"\n{'=' * 60}")
        print(f"Running model: {model_name}")
        print(f"{'=' * 60}")

        cv_model = build_pipeline(classifier)
        cv_metrics = run_cross_validation_on_training(cv_model, X_train, y_train)

        final_model = build_pipeline(classifier)
        final_model.fit(X_train, y_train)

        test_metrics, predictions_df, confusion_payload = evaluate_test_set(
            final_model,
            X_test,
            y_test,
            f_test,
        )

        predictions_df.insert(0, "model", model_name)
        all_test_predictions.append(predictions_df)
        all_confusions[model_name] = confusion_payload

        all_results[model_name] = {
            "cross_validation_on_training": cv_metrics,
            "held_out_test_metrics": test_metrics,
        }

        print("Held-out test results:")
        print(
            f"  Accuracy: {test_metrics['accuracy']}\n"
            f"  Macro F1: {test_metrics['macro_f1']}\n"
            f"  Weighted F1: {test_metrics['weighted_f1']}"
        )

    comparison_summary = {}
    for model_name, result in all_results.items():
        comparison_summary[model_name] = {
            "cv_accuracy_mean": result["cross_validation_on_training"]["accuracy"]["mean"],
            "cv_macro_f1_mean": result["cross_validation_on_training"]["f1_macro"]["mean"],
            "cv_weighted_f1_mean": result["cross_validation_on_training"]["f1_weighted"]["mean"],
            "test_accuracy": result["held_out_test_metrics"]["accuracy"],
            "test_macro_f1": result["held_out_test_metrics"]["macro_f1"],
            "test_weighted_f1": result["held_out_test_metrics"]["weighted_f1"],
        }

    final_report = {
        "dataset": {
            "total_samples": int(len(df)),
            "train_samples": int(len(X_train)),
            "test_samples": int(len(X_test)),
            "full_label_distribution": {
                k: int(v) for k, v in df["label"].value_counts().to_dict().items()
            },
            "train_label_distribution": {
                k: int(v) for k, v in y_train.value_counts().to_dict().items()
            },
            "test_label_distribution": {
                k: int(v) for k, v in y_test.value_counts().to_dict().items()
            },
        },
        "methodology": {
            "split_strategy": "80/20 stratified train-test split",
            "cross_validation_scope": "performed only on training split",
            "final_evaluation_scope": "performed only on held-out test split",
            "random_state": RANDOM_STATE,
            "cv_folds": CV_FOLDS,
        },
        "feature_representation": {
            "type": "TF-IDF",
            "analyzer": "char_wb",
            "ngram_range": [3, 5],
            "min_df": 2,
            "max_features": 50000,
            "sublinear_tf": True,
        },
        "models_compared": list(build_models().keys()),
        "comparison_summary": comparison_summary,
        "detailed_results": all_results,
    }

    with open(OUT_METRICS_JSON, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    combined_predictions_df = pd.concat(all_test_predictions, ignore_index=True)
    combined_predictions_df.to_csv(OUT_TEST_PREDICTIONS_CSV, index=False)

    save_confusion_by_model(all_confusions, OUT_CONFUSION_JSON)

    print(f"\nSaved metrics to {OUT_METRICS_JSON}")
    print(f"Saved test predictions to {OUT_TEST_PREDICTIONS_CSV}")
    print(f"Saved confusion matrices to {OUT_CONFUSION_JSON}")

    print(f"\n{'=' * 60}")
    print("Model comparison summary")
    print(f"{'=' * 60}")
    for model_name, summary in comparison_summary.items():
        print(
            f"{model_name}: "
            f"test_accuracy={summary['test_accuracy']}, "
            f"test_macro_f1={summary['test_macro_f1']}, "
            f"test_weighted_f1={summary['test_weighted_f1']}"
        )


if __name__ == "__main__":
    main()