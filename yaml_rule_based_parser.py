import os
import json
import re
from typing import Any, Dict, List, Tuple

import yaml

SRC_DIR = "k8s_yaml_only"
OUT_JSON = "rule_based_report.json"

PRIVILEGE_REGEX_RULES = {
    "privileged_true": r"privileged\s*:\s*true",
    "allow_privilege_escalation_true": r"allowPrivilegeEscalation\s*:\s*true",
    "run_as_non_root_false": r"runAsNonRoot\s*:\s*false",
    "host_network_true": r"hostNetwork\s*:\s*true",
    "host_pid_true": r"hostPID\s*:\s*true",
    "host_ipc_true": r"hostIPC\s*:\s*true",
    "docker_sock_mount": r"/var/run/docker\.sock",
    "host_path": r"hostPath\s*:",
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


def regex_findings_for_privilege(content: str) -> List[Dict[str, str]]:
    findings = []
    for rule_name, pattern in PRIVILEGE_REGEX_RULES.items():
        match = re.search(pattern, content, flags=re.IGNORECASE)
        if match:
            findings.append({
                "rule": rule_name,
                "match": match.group(0),
            })
    return findings


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


def walk_yaml(obj: Any, path: str = "") -> List[Tuple[str, str, Any]]:
    results: List[Tuple[str, str, Any]] = []

    if isinstance(obj, dict):
        for key, value in obj.items():
            current_path = f"{path}.{key}" if path else str(key)

            if isinstance(value, (dict, list)):
                results.extend(walk_yaml(value, current_path))
            else:
                results.append((current_path, str(key), value))

    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            current_path = f"{path}[{idx}]"
            if isinstance(item, (dict, list)):
                results.extend(walk_yaml(item, current_path))
            else:
                results.append((current_path, "[list_item]", item))

    return results


def analyze_secret_like_values(parsed_docs: List[Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    hardcoded_secret_findings: List[Dict[str, Any]] = []
    safe_secret_references: List[Dict[str, Any]] = []

    for doc_index, doc in enumerate(parsed_docs):
        if not isinstance(doc, (dict, list)):
            continue

        walked = walk_yaml(doc)

        for path, key, value in walked:
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

            if "env" in path.lower() and value_pattern_hits:
                reasons.append("env_literal_secret_value")

            if reasons:
                hardcoded_secret_findings.append({
                    "doc_index": doc_index,
                    "path": path,
                    "key": key,
                    "value": value_str,
                    "reasons": sorted(set(reasons)),
                })

    return hardcoded_secret_findings, safe_secret_references


def classify_file(content: str) -> Dict[str, Any]:
    parse_error = None
    parsed_docs: List[Any] = []

    try:
        parsed_docs = list(yaml.safe_load_all(content))
    except Exception as e:
        parse_error = str(e)

    privilege_findings = regex_findings_for_privilege(content)
    hardcoded_secret_findings: List[Dict[str, Any]] = []
    safe_secret_references: List[Dict[str, Any]] = []

    if parse_error is None:
        hardcoded_secret_findings, safe_secret_references = analyze_secret_like_values(parsed_docs)

    if privilege_findings:
        predicted_label = "privilege_exposure"
    elif hardcoded_secret_findings:
        predicted_label = "hardcoded_secret"
    else:
        predicted_label = "secure"

    return {
        "predicted_label": predicted_label,
        "parse_error": parse_error,
        "findings": {
            "privilege_findings": privilege_findings,
            "hardcoded_secret_findings": hardcoded_secret_findings,
            "safe_secret_references": safe_secret_references,
        },
    }


def main() -> None:
    report: List[Dict[str, Any]] = []

    for fname in sorted(os.listdir(SRC_DIR)):
        path = os.path.join(SRC_DIR, fname)
        if not os.path.isfile(path):
            continue

        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()

            result = classify_file(content)

            report.append({
                "file_name": fname,
                "predicted_label": result["predicted_label"],
                "parse_error": result["parse_error"],
                "findings": result["findings"],
            })

        except Exception as e:
            report.append({
                "file_name": fname,
                "predicted_label": "error",
                "parse_error": str(e),
                "findings": {},
            })

    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"Saved JSON report to {OUT_JSON}")


if __name__ == "__main__":
    main()