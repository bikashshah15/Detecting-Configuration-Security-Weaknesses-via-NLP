# Detecting Configuration Security Weaknesses via NLP

This repository detects security weaknesses in Kubernetes YAML configurations using three complementary approaches:

1. Rule-based structural analysis for explicit privilege escalation issues
2. Rule-based regex and YAML parsing for hardcoded secret detection
3. A TF-IDF + classical ML pipeline for text-based classification of YAML files

The project classifies Kubernetes manifests into:

- `secure`
- `hardcoded_secret`
- `privilege_exposure`

It also includes evaluation scripts, merged reporting, and demo manifests that show vulnerable and fixed configurations.

## Repository Overview

### Main scripts

- `clone_repos.sh`: clones repositories listed in `repos.txt`
- `extract_yaml.sh`: extracts `.yaml` and `.yml` files from cloned repositories
- `filter_k8s_yaml.py`: keeps only Kubernetes manifests
- `label_k8s_yaml.py`: generates heuristic labels for the dataset
- `rule_based_parser.py`: structural rule-based scanner for privilege-related findings
- `yaml_rule_based_parser.py`: regex/YAML-based scanner for privilege and hardcoded-secret findings
- `merge_reports.py`: merges the two rule-based reports into a consolidated report
- `rule_based_evaluation.py`: evaluates the consolidated rule-based detector against labeled data
- `tfidf_classifier.py`: trains and evaluates TF-IDF ML classifiers
- `comparison_evaluation.py`: compares rule-based, NLP, and hybrid prediction strategies
- `hybrid_detection_pipeline.py`: scans YAML files using rules plus a trained serialized NLP model
- `hybrid_pipeline_evaluation.py`: evaluates `hybrid_detection_report.json` against `k8s_labels.csv`

### Example and output files

- `demo/attack/vulnerable.yaml`: intentionally insecure example
- `demo/attack/fixed.yaml`: remediated version of the example
- `security_report.json`: structural rule-based scan output
- `rule_based_report.json`: regex/YAML rule-based scan output
- `consolidated_report.json`: merged rule-based output
- `rule_based_metrics.json`: evaluation metrics for the merged rule-based detector
- `tfidf_metrics.json`: ML training/evaluation metrics
- `tfidf_test_predictions.csv`: held-out test predictions from all ML models
- `comparison_metrics.json`: comparison metrics for rule-based, NLP, and hybrid strategies
- `comparison_predictions.csv`: aligned rule/NLP/hybrid predictions
- `comparison_mismatches.csv`: examples where comparison predictions differ from ground truth
- `hybrid_detection_report.json`: generated output from the hybrid detection pipeline
- `hybrid_pipeline_metrics.json`: full-dataset evaluation metrics for the generated hybrid pipeline report
- `hybrid_pipeline_mismatches.csv`: mislabeled or missing items from hybrid pipeline evaluation

## Detection Scope

### Privilege exposure checks

The rule-based pipeline looks for risky Kubernetes settings such as:

- `privileged: true`
- `allowPrivilegeEscalation: true`
- `hostNetwork: true`
- `hostPID: true`
- mounting `/var/run/docker.sock`

### Hardcoded secret checks

The YAML-aware scanners look for:

- literal values assigned to keys like `password`, `token`, `apiKey`, `secret`
- token-like patterns such as AWS keys, GitHub tokens, OpenAI keys, JWT-like strings, and long base64-like values
- Kubernetes secret references are treated separately so they are not confused with hardcoded secrets

## Prerequisites

- Python 3.9+
- `git`
- shell environment capable of running `bash`

Install Python dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install pyyaml pandas numpy scikit-learn
```

## Important Notes Before Running

Most scripts use hard-coded input/output paths defined near the top of each file. The default workflow expects these directories:

- `repos/`
- `all_yaml_raw/`
- `k8s_yaml_only/`

If your dataset lives somewhere else, update the constants in the relevant script before running it.

Also note:

- `hybrid_detection_pipeline.py` expects a serialized sklearn model named `best_nlp_model.pkl`
- `best_nlp_model.pkl` is available in the repository root
- `tfidf_classifier.py` evaluates models and writes metrics/predictions, but it does not save a deployable pickle by default

## End-to-End Workflow

### 1. Clone source repositories

Populate `repos.txt` with one Git repository URL per line, then run:

```bash
bash clone_repos.sh
```

This creates a local `repos/` directory and performs shallow clones.

### 2. Extract all YAML files

```bash
bash extract_yaml.sh
```

This copies all YAML files into `all_yaml_raw/` and prefixes filenames with the source repository path to avoid collisions.

### 3. Keep only Kubernetes manifests

```bash
python3 filter_k8s_yaml.py
```

This reads `all_yaml_raw/` and copies only Kubernetes YAML files into `k8s_yaml_only/`.

### 4. Generate dataset labels

```bash
python3 label_k8s_yaml.py
```

This produces `k8s_labels.csv` with columns:

- `file_name`
- `label`
- `findings`
- `safe_secret_refs_detected`

### 5. Run structural rule-based scanning

```bash
python3 rule_based_parser.py
```

Output:

- `security_report.json`

This scanner focuses on explicit privilege-related misconfigurations in Kubernetes pod specs.

### 6. Run regex/YAML rule-based scanning

```bash
python3 yaml_rule_based_parser.py
```

Output:

- `rule_based_report.json`

This scanner combines regex checks and YAML traversal to detect privilege issues and hardcoded secrets.

### 7. Merge the rule-based reports

```bash
python3 merge_reports.py
```

Output:

- `consolidated_report.json`

The merged report resolves the final per-file label using this priority:

1. `privilege_exposure`
2. `hardcoded_secret`
3. `secure`

### 8. Evaluate the rule-based system

```bash
python3 rule_based_evaluation.py
```

Outputs:

- `rule_based_metrics.json`
- `rule_based_mismatches.csv`

### 9. Train and evaluate the NLP classifier

```bash
python3 tfidf_classifier.py
```

Outputs:

- `tfidf_metrics.json`
- `tfidf_test_predictions.csv`
- `tfidf_confusion_matrix.json`

This script compares:

- logistic regression
- linear SVM
- random forest

using character-level TF-IDF features on YAML text.

### 10. Compare rule-based, NLP, and hybrid strategies

```bash
python3 comparison_evaluation.py
```

Outputs:

- `comparison_metrics.json`
- `comparison_predictions.csv`
- `comparison_mismatches.csv`

This comparison evaluates:

- pure rule-based predictions
- pure NLP predictions
- `hybrid_rule_first`
- `hybrid_privilege_override`

### 11. Run the deployable hybrid detector

After placing a trained sklearn-compatible model at `best_nlp_model.pkl`, run:

```bash
python3 hybrid_detection_pipeline.py
```

Output:

- `hybrid_detection_report.json`

This pipeline:

- uses rules for explicit privilege findings
- uses the NLP model for text classification
- combines both into a final label and severity
- reports hardcoded secret findings and safe Kubernetes secret references

### 12. Evaluate the generated hybrid pipeline report

If `hybrid_detection_report.json` was generated from `hybrid_detection_pipeline.py` for the same dataset as `k8s_labels.csv`, run:

```bash
python3 hybrid_pipeline_evaluation.py
```

Outputs:

- `hybrid_pipeline_metrics.json`
- `hybrid_pipeline_mismatches.csv`

This evaluates the generated pipeline predictions directly against the dataset labels.

## Quick Demo

The `demo/attack/` directory includes a vulnerable and a fixed manifest.

### Vulnerable example

`demo/attack/vulnerable.yaml` includes:

- `privileged: true`
- `hostPID: true`
- `hostNetwork: true`
- `/var/run/docker.sock` mounted into the container

These are classic privilege-exposure indicators.

### Fixed example

`demo/attack/fixed.yaml` changes the configuration to safer defaults, including:

- `privileged: false`
- `allowPrivilegeEscalation: false`
- `hostPID: false`
- `hostNetwork: false`
- use of a Kubernetes `secretName` reference instead of exposing host resources

### How to try the demo

Option 1: copy one of the demo files into `k8s_yaml_only/` and run the rule-based scanners.

```bash
mkdir -p k8s_yaml_only
cp demo/attack/vulnerable.yaml k8s_yaml_only/demo-vulnerable.yaml
python3 rule_based_parser.py
python3 yaml_rule_based_parser.py
python3 merge_reports.py
```

Option 2: if you already have `best_nlp_model.pkl`, also run:

```bash
python3 hybrid_detection_pipeline.py
```

## How to Read the Outputs

### `consolidated_report.json`

Contains:

- summary counts
- file-level final labels
- severity
- structural issues
- privilege findings
- hardcoded secret findings
- safe secret references

Example fields in each record:

```json
{
  "file_name": "example.yaml",
  "final_label": "hardcoded_secret",
  "final_severity": "MEDIUM",
  "label_from_structural": "secure",
  "label_from_regex": "hardcoded_secret",
  "parse_error": null
}
```

### `tfidf_metrics.json`

Contains:

- dataset sizes
- class distributions
- train/test methodology
- cross-validation metrics
- held-out test metrics for each model

### `comparison_metrics.json`

Contains side-by-side metrics for rule-based, NLP, and hybrid methods on the aligned comparison subset.

From the checked-in metrics in this repository:

- rule-based accuracy: `0.9102`
- NLP accuracy: `0.9576`
- aligned evaluation set size: `590`
- NLP model used in comparison: `linear_svm`

### `rule_based_metrics.json`

Contains merged rule-based evaluation metrics over the full labeled dataset. The checked-in report shows:

- aligned files: `2949`
- rule-based accuracy: `0.901`

### `hybrid_pipeline_metrics.json`

Contains full-dataset evaluation metrics for the generated hybrid detection pipeline report.

From the checked-in metrics in this repository:

- aligned files: `2949`
- hybrid pipeline accuracy: `0.9875`
- macro F1: `0.9778`
- weighted F1: `0.9875`

## Typical Usage Patterns

### Use only the rule-based scanner

Best when you want fast, explainable detection of explicit risky settings.

```bash
python3 rule_based_parser.py
python3 yaml_rule_based_parser.py
python3 merge_reports.py
```

### Train and compare NLP models

Best when you want empirical classification performance on a labeled dataset.

```bash
python3 tfidf_classifier.py
```

### Compare rule-based vs NLP vs hybrid strategies

Best when you already have:

- `k8s_labels.csv`
- `consolidated_report.json`
- `tfidf_test_predictions.csv`

Then run:

```bash
python3 comparison_evaluation.py
```

### Evaluate an existing generated hybrid pipeline report

Best when `hybrid_detection_report.json` already came from `hybrid_detection_pipeline.py` and corresponds to the same files in `k8s_labels.csv`.

```bash
python3 hybrid_pipeline_evaluation.py
```

### Scan a directory with the hybrid detector

Best when you have already trained and serialized a model to `best_nlp_model.pkl`.

```bash
python3 hybrid_detection_pipeline.py
```

## Current Model Setup

The NLP training pipeline uses:

- TF-IDF character n-grams
- analyzer: `char_wb`
- n-gram range: `3-5`
- stratified `80/20` train-test split
- `5`-fold cross-validation on the training split only

Compared models:

- `logistic_regression`
- `linear_svm`
- `random_forest`

Based on the results, `linear_svm` is the strongest of the three on the held-out test split.

## Limitations

- `tfidf_classifier.py` does not export a trained `.pkl` model by default
- labeling in `label_k8s_yaml.py` is heuristic and may contain noise
- the rule-based detector currently focuses on a narrow but important subset of Kubernetes security weaknesses

## Future Plans

- expand coverage to additional Kubernetes security anti-patterns
- make the models more robust

## File Structure

```text
.
├── README.md
├── clone_repos.sh
├── extract_yaml.sh
├── filter_k8s_yaml.py
├── label_k8s_yaml.py
├── rule_based_parser.py
├── yaml_rule_based_parser.py
├── merge_reports.py
├── rule_based_evaluation.py
├── tfidf_classifier.py
├── comparison_evaluation.py
├── hybrid_detection_pipeline.py
├── hybrid_pipeline_evaluation.py
├── demo/
│   └── attack/
│       ├── vulnerable.yaml
│       └── fixed.yaml
└── output artifacts...
```

## Summary

This repository provides a complete mini-pipeline for:

- collecting Kubernetes YAML files
- labeling them for security weakness categories
- detecting issues with rules
- classifying YAMLs with NLP/ML
- comparing rule-based, NLP, and hybrid strategies
- evaluating the generated hybrid detection pipeline report

If you want the fastest path through the project, run the workflow in this order:

```bash
bash clone_repos.sh
bash extract_yaml.sh
python3 filter_k8s_yaml.py
python3 label_k8s_yaml.py
python3 rule_based_parser.py
python3 yaml_rule_based_parser.py
python3 merge_reports.py
python3 rule_based_evaluation.py
python3 tfidf_classifier.py
python3 comparison_evaluation.py
python3 hybrid_detection_pipeline.py
python3 hybrid_pipeline_evaluation.py
```
