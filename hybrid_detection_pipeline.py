import os
import re
import json
import pickle
from typing import Any, Dict, List, Optional

import yaml

INPUT_DIR = "k8s_yaml_only"
OUTPUT_JSON = "hybrid_detection_report.json"
NLP_MODEL_PATH = "best_nlp_model.pkl"

RULE_PATTERNS = {
    "privileged_true": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
    "allow_privilege_escalation_true": re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.IGNORECASE),
    "host_network_true": re.compile(r"hostNetwork\s*:\s*true", re.IGNORECASE),
    "host_pid_true": re.compile(r"hostPID\s*:\s*true", re.IGNORECASE),
    "docker_sock_mount": re.compile(r"/var/run/docker\.sock", re.IGNORECASE),
}

SEVERITY_MAP = {
    "privileged_true": "CRITICAL",
    "docker_sock_mount": "CRITICAL",
    "allow_privilege_escalation_true": "HIGH",
    "host_network_true": "HIGH",
    "host_pid_true": "HIGH",
}

REMEDIATION_MAP = {
    "privileged_true": [
        "Set securityContext.privileged to false.",
        "Avoid privileged containers unless absolutely necessary.",
    ],
    "allow_privilege_escalation_true": [
        "Set allowPrivilegeEscalation to false.",
    ],
    "host_network_true": [
        "Disable hostNetwork unless there is a strict operational need.",
    ],
    "host_pid_true": [
        "Disable hostPID unless process namespace sharing is explicitly required.",
    ],
    "docker_sock_mount": [
        "Remove the /var/run/docker.sock mount.",
        "Avoid exposing container runtime control to workloads.",
    ],
}

EVIDENCE_HINTS = {
    "privileged_true": "privileged: true",
    "allow_privilege_escalation_true": "allowPrivilegeEscalation: true",
    "host_network_true": "hostNetwork: true",
    "host_pid_true": "hostPID: true",
    "docker_sock_mount": "/var/run/docker.sock",
}

SEVERITY_ORDER = {
    "NONE": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

SECRET_LIKE_KEY_PATTERN = re.compile(
    r"(password|passwd|pwd|token|api[_-]?key|access[_-]?key|secret|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)

SAFE_SECRET_REFERENCE_KEYS = {
    "secretName",
    "secretKeyRef",
    "imagePullSecrets",
    "envFrom",
    "valueFrom",
    "secretRef",
}

SAFE_REFERENCE_PATH_PARTS = {
    "secretKeyRef",
    "valueFrom",
    "envFrom",
    "secretRef",
    "imagePullSecrets",
}

SECRET_VALUE_PATTERNS = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{10,}\b"),
    "github_token": re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "jwt_like_token": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z0-9._-]+\b"),
    "long_base64_like": re.compile(r"^[A-Za-z0-9+/=]{32,}$"),
}

PLACEHOLDER_VALUES = {
    "changeme",
    "your-password",
    "your_token_here",
    "example",
    "examplekey",
    "exampletoken",
    "password",
    "token",
    "secret",
    "my-secret",
    "dummy",
    "test",
    "null",
    "none",
    "",
}

def is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool))


def stringify_scalar(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_nlp_model(model_path: str):
    if not os.path.isfile(model_path):
        raise FileNotFoundError(
            f"NLP model file not found: {model_path}\n"
            f"Save your trained sklearn pipeline to this path first."
        )

    with open(model_path, "rb") as f:
        model = pickle.load(f)
    return model


def walk_yaml(obj: Any, path: str = "") -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else str(key)

            if isinstance(value, (dict, list)):
                results.extend(walk_yaml(value, current_path))
            else:
                results.append({
                    "path": current_path,
                    "key": str(key),
                    "value": value,
                })

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            current_path = f"{path}[{idx}]"
            if isinstance(item, (dict, list)):
                results.extend(walk_yaml(item, current_path))
            else:
                results.append({
                    "path": current_path,
                    "key": "[list_item]",
                    "value": item,
                })

    return results


def is_probably_safe_reference(path: str, key: str, value: Any) -> bool:
    path_parts = path.replace("[", ".[").split(".")

    if key in SAFE_SECRET_REFERENCE_KEYS:
        return True

    if any(part in SAFE_REFERENCE_PATH_PARTS for part in path_parts):
        return True

    if key == "secretName" and is_scalar(value):
        return True

    return False


def matches_secret_value_patterns(value_str: str) -> List[str]:
    matched = []
    for label, pattern in SECRET_VALUE_PATTERNS.items():
        if pattern.search(value_str):
            matched.append(label)
    return matched


def analyze_secret_reporting_only(parsed_docs: List[Any]) -> Dict[str, List[Dict[str, Any]]]:
    
    hardcoded_secret_findings: List[Dict[str, Any]] = []
    safe_secret_references: List[Dict[str, Any]] = []

    for doc_index, doc in enumerate(parsed_docs):
        if not isinstance(doc, (dict, list)):
            continue

        walked = walk_yaml(doc)

        for item in walked:
            path = item["path"]
            key = item["key"]
            value = item["value"]
            value_str = stringify_scalar(value)

            if is_probably_safe_reference(path, key, value):
                if SECRET_LIKE_KEY_PATTERN.search(key) or key in SAFE_SECRET_REFERENCE_KEYS:
                    safe_secret_references.append({
                        "doc_index": doc_index,
                        "path": path,
                        "key": key,
                        "value": value_str,
                        "reason": "kubernetes_secret_reference",
                    })
                continue

            if not is_scalar(value):
                continue

            lowered = value_str.lower()
            if lowered in PLACEHOLDER_VALUES:
                continue

            reasons = []

            if SECRET_LIKE_KEY_PATTERN.search(key) and len(value_str) >= 4:
                reasons.append("secret_like_key_with_literal_value")

            value_pattern_hits = matches_secret_value_patterns(value_str)
            reasons.extend(value_pattern_hits)

            if reasons:
                hardcoded_secret_findings.append({
                    "doc_index": doc_index,
                    "path": path,
                    "key": key,
                    "value": value_str,
                    "reasons": sorted(set(reasons)),
                })

    return {
        "hardcoded_secret_findings": hardcoded_secret_findings,
        "safe_secret_references": safe_secret_references,
    }


def find_rule_matches(content: str) -> List[Dict[str, Any]]:
    findings = []

    for finding_type, pattern in RULE_PATTERNS.items():
        for match in pattern.finditer(content):
            findings.append({
                "type": finding_type,
                "severity": SEVERITY_MAP[finding_type],
                "evidence": match.group(0),
                "detected_by": "rule",
                "remediation": REMEDIATION_MAP[finding_type],
            })
            break 

    return findings


def label_from_rules(privilege_findings: List[Dict[str, Any]]) -> str:
    return "privilege_exposure" if privilege_findings else "secure"


def highest_severity(privilege_findings: List[Dict[str, Any]], nlp_label: str, hardcoded_secret_findings: List[Dict[str, Any]]) -> str:
    if privilege_findings:
        highest = max((f["severity"] for f in privilege_findings), key=lambda x: SEVERITY_ORDER[x])
        return highest

    if nlp_label == "hardcoded_secret":
        if hardcoded_secret_findings:
            high_confidence_secret = any(
                any(reason in item.get("reasons", []) for reason in [
                    "aws_access_key",
                    "openai_key",
                    "github_token",
                    "google_api_key",
                    "slack_token",
                    "jwt_like_token",
                ])
                for item in hardcoded_secret_findings
            )
            return "HIGH" if high_confidence_secret else "MEDIUM"
        return "MEDIUM"

    return "NONE"


def classify_with_nlp(model, content: str) -> Dict[str, Optional[Any]]:
    result = {
        "label_from_nlp": None,
        "nlp_confidence": None,
        "nlp_note": None,
    }

    pred = model.predict([content])[0]
    result["label_from_nlp"] = str(pred)

    if hasattr(model, "predict_proba"):
        try:
            proba = model.predict_proba([content])[0]
            classes = list(model.classes_)
            pred_idx = classes.index(pred)
            result["nlp_confidence"] = round(float(proba[pred_idx]), 4)
        except Exception:
            pass

    elif hasattr(model, "decision_function"):
        try:
            decision = model.decision_function([content])

            if getattr(decision, "ndim", 1) == 1:
                score = float(decision[0])
                result["nlp_confidence"] = round(abs(score), 4)
            else:
                pred_idx = list(model.classes_).index(pred)
                score = float(decision[0][pred_idx])
                result["nlp_confidence"] = round(abs(score), 4)
        except Exception:
            pass

    result["nlp_note"] = (
        "NLP classifier prediction based on full YAML text patterns."
    )
    return result


def make_summary(report_items: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        "total_files": len(report_items),
        "flagged_files": 0,
        "clean_files": 0,
        "by_label": {
            "privilege_exposure": 0,
            "hardcoded_secret": 0,
            "secure": 0,
        },
        "by_severity": {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "NONE": 0,
        },
        "total_privilege_findings": 0,
        "total_hardcoded_secret_findings": 0,
    }

    for item in report_items:
        final_label = item["final_label"]
        final_severity = item["final_severity"]

        summary["by_label"][final_label] = summary["by_label"].get(final_label, 0) + 1
        summary["by_severity"][final_severity] = summary["by_severity"].get(final_severity, 0) + 1

        if final_label == "secure":
            summary["clean_files"] += 1
        else:
            summary["flagged_files"] += 1

        summary["total_privilege_findings"] += len(item.get("privilege_findings", []))
        summary["total_hardcoded_secret_findings"] += len(item.get("hardcoded_secret_findings", []))

    return summary

def analyze_file(file_name: str, file_path: str, nlp_model) -> Dict[str, Any]:
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except UnicodeDecodeError:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

    parse_error = None
    parsed_docs: List[Any] = []

    try:
        parsed_docs = list(yaml.safe_load_all(content))
    except Exception as e:
        parse_error = str(e)

    privilege_findings = find_rule_matches(content)
    label_from_structural = label_from_rules(privilege_findings)

    secret_report = {
        "hardcoded_secret_findings": [],
        "safe_secret_references": [],
    }
    if parse_error is None:
        secret_report = analyze_secret_reporting_only(parsed_docs)

    nlp_result = classify_with_nlp(nlp_model, content)
    label_from_nlp = nlp_result["label_from_nlp"] or "secure"

    if label_from_structural == "privilege_exposure":
        final_label = "privilege_exposure"
    else:
        final_label = label_from_nlp

    final_severity = highest_severity(
        privilege_findings=privilege_findings,
        nlp_label=label_from_nlp,
        hardcoded_secret_findings=secret_report["hardcoded_secret_findings"],
    )

    return {
        "file_name": file_name,
        "final_label": final_label,
        "final_severity": final_severity,
        "label_from_structural": label_from_structural,
        "label_from_nlp": label_from_nlp,
        "nlp_confidence": nlp_result["nlp_confidence"],
        "nlp_note": nlp_result["nlp_note"],
        "parse_error": parse_error,
        "privilege_findings": privilege_findings,
        "hardcoded_secret_findings": secret_report["hardcoded_secret_findings"],
        "safe_secret_references": secret_report["safe_secret_references"],
    }


def main() -> None:
    nlp_model = load_nlp_model(NLP_MODEL_PATH)

    if not os.path.isdir(INPUT_DIR):
        raise FileNotFoundError(f"Input directory not found: {INPUT_DIR}")

    report_items: List[Dict[str, Any]] = []

    for file_name in sorted(os.listdir(INPUT_DIR)):
        file_path = os.path.join(INPUT_DIR, file_name)
        if not os.path.isfile(file_path):
            continue
        if not file_name.endswith((".yaml", ".yml")):
            continue

        result = analyze_file(file_name, file_path, nlp_model)
        report_items.append(result)

    final_report = {
        "summary": make_summary(report_items),
        "findings": report_items,
    }

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(final_report, f, indent=2)

    print(f"Saved hybrid detection report to {OUTPUT_JSON}")


if __name__ == "__main__":
    main()