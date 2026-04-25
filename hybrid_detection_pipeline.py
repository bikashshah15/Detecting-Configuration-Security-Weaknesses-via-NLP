import os
import re
import json
import pickle
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

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

REASONING_MAP = {
    "privileged_true": "A privileged container bypasses many of the isolation boundaries that Kubernetes and the container runtime normally enforce.",
    "allow_privilege_escalation_true": "This setting allows a process to gain more privileges than it started with, weakening least-privilege controls inside the container.",
    "host_network_true": "The pod joins the host network namespace, so it is no longer isolated behind normal pod networking boundaries.",
    "host_pid_true": "The pod can interact with the host PID namespace, exposing process visibility that regular workloads should not have.",
    "docker_sock_mount": "Mounting the Docker socket exposes direct control over the container runtime from inside the workload.",
    "hardcoded_secret": "A literal credential in YAML can be read by anyone who can view the manifest, logs, backups, or source control history.",
}

CONSEQUENCE_MAP = {
    "privileged_true": [
        "An attacker who compromises the container may gain near-host-level control.",
        "The workload can access sensitive host resources that should remain isolated.",
    ],
    "allow_privilege_escalation_true": [
        "A compromised process may elevate its privileges inside the container.",
        "Defense-in-depth controls around runtime privilege reduction become less effective.",
    ],
    "host_network_true": [
        "The workload may access host-only services and listen on host interfaces.",
        "Network isolation assumptions between pods and the node are reduced.",
    ],
    "host_pid_true": [
        "The workload can inspect or signal host processes.",
        "Host-level process information becomes visible to the container.",
    ],
    "docker_sock_mount": [
        "A compromised workload may start privileged containers or escape to the host.",
        "Direct runtime access can lead to full control of other containers on the node.",
    ],
    "hardcoded_secret": [
        "The exposed secret can be reused by anyone who obtains the manifest.",
        "Rotation and incident response may be required if the value was committed or shared.",
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
            start_line, end_line = get_line_span_from_offsets(content, match.start(), match.end())
            findings.append({
                "type": finding_type,
                "severity": SEVERITY_MAP[finding_type],
                "evidence": match.group(0),
                "detected_by": "rule",
                "start_line": start_line,
                "end_line": end_line,
                "reasoning": REASONING_MAP[finding_type],
                "consequences": CONSEQUENCE_MAP[finding_type],
                "remediation": REMEDIATION_MAP[finding_type],
            })

    return findings


def get_line_span_from_offsets(content: str, start_offset: int, end_offset: int) -> Tuple[int, int]:
    start_line = content.count("\n", 0, start_offset) + 1
    end_line = content.count("\n", 0, max(end_offset - 1, 0)) + 1
    return start_line, end_line


def secret_finding_severity(secret_finding: Dict[str, Any]) -> str:
    high_confidence_reasons = {
        "aws_access_key",
        "openai_key",
        "github_token",
        "google_api_key",
        "slack_token",
        "jwt_like_token",
    }

    reasons = set(secret_finding.get("reasons", []))
    return "HIGH" if reasons & high_confidence_reasons else "MEDIUM"


def secret_finding_remediation(secret_finding: Dict[str, Any]) -> List[str]:
    reasons = set(secret_finding.get("reasons", []))
    guidance = [
        "Move this sensitive value into a Kubernetes Secret instead of keeping it inline in the manifest.",
        "Reference the secret through valueFrom.secretKeyRef or another supported secret reference.",
        "Rotate the exposed credential if this value was ever committed, shared, or deployed.",
    ]

    if reasons & {"aws_access_key", "openai_key", "github_token", "google_api_key", "slack_token", "jwt_like_token"}:
        guidance.insert(0, "Treat this credential as exposed and replace it with a newly generated secret.")

    return guidance


def secret_finding_reasoning(secret_finding: Dict[str, Any]) -> str:
    reasons = set(secret_finding.get("reasons", []))
    if reasons & {"aws_access_key", "openai_key", "github_token", "google_api_key", "slack_token", "jwt_like_token"}:
        return "The value matches a known credential pattern, so this is likely to be a real secret rather than a harmless placeholder."
    return REASONING_MAP["hardcoded_secret"]


def secret_finding_consequences(secret_finding: Dict[str, Any]) -> List[str]:
    reasons = set(secret_finding.get("reasons", []))
    consequences = list(CONSEQUENCE_MAP["hardcoded_secret"])
    if reasons & {"aws_access_key", "openai_key", "github_token", "google_api_key", "slack_token", "jwt_like_token"}:
        consequences.insert(0, "This credential may allow unauthorized access to external systems or cloud resources.")
    return consequences


def locate_secret_line_numbers(content: str, key: str, value: Any) -> List[int]:
    lines = content.splitlines()
    key_lower = str(key).strip().lower()
    value_lower = stringify_scalar(value).lower()

    exact_matches: List[int] = []
    key_matches: List[int] = []

    for idx, line in enumerate(lines, start=1):
        lowered = line.lower()
        if key_lower and key_lower in lowered:
            key_matches.append(idx)
            if value_lower and value_lower in lowered:
                exact_matches.append(idx)

    if exact_matches:
        return exact_matches[:3]
    return key_matches[:3]


def enrich_secret_findings_with_locations(content: str, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    enriched: List[Dict[str, Any]] = []

    for finding in findings:
        updated = dict(finding)
        line_numbers = locate_secret_line_numbers(
            content=content,
            key=updated.get("key", ""),
            value=updated.get("value", ""),
        )
        updated["severity"] = secret_finding_severity(updated)
        updated["reasoning"] = secret_finding_reasoning(updated)
        updated["consequences"] = secret_finding_consequences(updated)
        updated["remediation"] = secret_finding_remediation(updated)
        updated["line_numbers"] = line_numbers
        if line_numbers:
            updated["start_line"] = line_numbers[0]
            updated["end_line"] = line_numbers[-1]
        else:
            updated["start_line"] = None
            updated["end_line"] = None
        enriched.append(updated)

    return enriched


def build_line_annotations(
    privilege_findings: List[Dict[str, Any]],
    hardcoded_secret_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    annotations: List[Dict[str, Any]] = []

    for finding in privilege_findings:
        annotations.append({
            "category": "privilege_exposure",
            "type": finding["type"],
            "severity": finding["severity"],
            "start_line": finding.get("start_line"),
            "end_line": finding.get("end_line"),
            "evidence": finding.get("evidence"),
            "reasoning": finding.get("reasoning"),
            "consequences": finding.get("consequences", []),
        })

    for finding in hardcoded_secret_findings:
        annotations.append({
            "category": "hardcoded_secret",
            "type": "hardcoded_secret",
            "severity": finding.get("severity", "MEDIUM"),
            "start_line": finding.get("start_line"),
            "end_line": finding.get("end_line"),
            "evidence": f'{finding.get("key", "")}: {finding.get("value", "")}',
            "reasons": finding.get("reasons", []),
            "reasoning": finding.get("reasoning"),
            "consequences": finding.get("consequences", []),
        })

    annotations.sort(
        key=lambda item: (
            item.get("start_line") is None,
            item.get("start_line") or 10**9,
            -(item.get("end_line") or 0),
        )
    )
    return annotations


def suggested_code_changes(annotation: Dict[str, Any]) -> List[str]:
    annotation_type = annotation.get("type")

    if annotation_type == "privileged_true":
        return [
            "Change `privileged: true` to `privileged: false` inside the container securityContext.",
            "Keep the container unprivileged unless there is a documented operational need.",
        ]
    if annotation_type == "allow_privilege_escalation_true":
        return [
            "Change `allowPrivilegeEscalation: true` to `allowPrivilegeEscalation: false`.",
            "Set this explicitly in the container securityContext to prevent privilege gain.",
        ]
    if annotation_type == "host_network_true":
        return [
            "Change `hostNetwork: true` to `hostNetwork: false` or remove the field.",
            "Use normal pod networking unless host namespace access is strictly required.",
        ]
    if annotation_type == "host_pid_true":
        return [
            "Change `hostPID: true` to `hostPID: false` or remove the field.",
            "Avoid sharing the host PID namespace with the pod.",
        ]
    if annotation_type == "docker_sock_mount":
        return [
            "Remove the `/var/run/docker.sock` mount from volumes and volumeMounts.",
            "Replace direct Docker socket access with a safer build or runtime integration.",
        ]
    if annotation_type == "hardcoded_secret":
        evidence = annotation.get("evidence", "")
        key_name = evidence.split(":", 1)[0].strip() or "SECRET_VALUE"
        return [
            "Move the literal secret into a Kubernetes Secret resource.",
            f"Replace the inline value with a `valueFrom.secretKeyRef` reference for `{key_name}`.",
            "Rotate the credential if this YAML was committed or shared.",
        ]

    return []


def build_highlighted_lines(content: str, annotations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    lines = content.splitlines()
    highlighted = []

    for line_number, text in enumerate(lines, start=1):
        matches = [
            annotation for annotation in annotations
            if annotation.get("start_line") is not None
            and annotation["start_line"] <= line_number <= annotation["end_line"]
        ]
        enriched_matches = []
        for match in matches:
            enriched_match = dict(match)
            enriched_match["suggested_code_changes"] = suggested_code_changes(enriched_match)
            enriched_matches.append(enriched_match)

        severities = [match["severity"] for match in enriched_matches]
        line_severity = "NONE"
        if severities:
            line_severity = max(severities, key=lambda severity: SEVERITY_ORDER[severity])

        highlighted.append({
            "line_number": line_number,
            "text": text,
            "severity": line_severity,
            "matches": enriched_matches,
        })

    return highlighted


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

    return analyze_yaml_content(content=content, file_name=file_name, nlp_model=nlp_model, parse_error=parse_error, parsed_docs=parsed_docs)


def analyze_yaml_content(
    content: str,
    file_name: str = "submitted.yaml",
    nlp_model=None,
    parse_error: Optional[str] = None,
    parsed_docs: Optional[List[Any]] = None,
) -> Dict[str, Any]:
    if nlp_model is None:
        nlp_model = get_cached_nlp_model()

    if parsed_docs is None and parse_error is None:
        try:
            parsed_docs = list(yaml.safe_load_all(content))
        except Exception as e:
            parse_error = str(e)
            parsed_docs = []

    privilege_findings = find_rule_matches(content)
    label_from_structural = label_from_rules(privilege_findings)

    secret_report = {
        "hardcoded_secret_findings": [],
        "safe_secret_references": [],
    }
    if parse_error is None and parsed_docs is not None:
        secret_report = analyze_secret_reporting_only(parsed_docs)

    enriched_secret_findings = enrich_secret_findings_with_locations(
        content,
        secret_report["hardcoded_secret_findings"],
    )

    nlp_result = classify_with_nlp(nlp_model, content)
    label_from_nlp = nlp_result["label_from_nlp"] or "secure"

    if label_from_structural == "privilege_exposure":
        final_label = "privilege_exposure"
    else:
        final_label = label_from_nlp

    final_severity = highest_severity(
        privilege_findings=privilege_findings,
        nlp_label=label_from_nlp,
        hardcoded_secret_findings=enriched_secret_findings,
    )

    annotations = build_line_annotations(privilege_findings, enriched_secret_findings)

    return {
        "file_name": file_name,
        "submitted_yaml": content,
        "final_label": final_label,
        "final_severity": final_severity,
        "label_from_structural": label_from_structural,
        "label_from_nlp": label_from_nlp,
        "nlp_confidence": nlp_result["nlp_confidence"],
        "nlp_note": nlp_result["nlp_note"],
        "parse_error": parse_error,
        "privilege_findings": privilege_findings,
        "hardcoded_secret_findings": enriched_secret_findings,
        "safe_secret_references": secret_report["safe_secret_references"],
        "line_annotations": annotations,
        "highlighted_lines": build_highlighted_lines(content, annotations),
    }


@lru_cache(maxsize=1)
def get_cached_nlp_model():
    return load_nlp_model(NLP_MODEL_PATH)


def main() -> None:
    nlp_model = get_cached_nlp_model()

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
