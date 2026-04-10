import os
import csv
import re

SRC_DIR = "k8s_yaml_only"
OUT_CSV = "k8s_labels.csv"

PRIVILEGE_RULES = {
    "privileged_true": r"privileged\s*:\s*true",
    "allow_privilege_escalation_true": r"allowPrivilegeEscalation\s*:\s*true",
    "run_as_non_root_false": r"runAsNonRoot\s*:\s*false",
    "host_network_true": r"hostNetwork\s*:\s*true",
    "host_pid_true": r"hostPID\s*:\s*true",
    "host_ipc_true": r"hostIPC\s*:\s*true",
    "docker_sock_mount": r"/var/run/docker\.sock",
    "host_path": r"hostPath\s*:",
}

SAFE_SECRET_REFERENCE_RULES = {
    "safe_secret_name": r"\bsecretName\s*:\s*[A-Za-z0-9._-]+",
    "safe_secret_key_ref": r"\bsecretKeyRef\s*:",
    "safe_value_from": r"\bvalueFrom\s*:",
    "safe_env_from": r"\benvFrom\s*:",
    "safe_secret_ref": r"\bsecretRef\s*:",
    "safe_image_pull_secrets": r"\bimagePullSecrets\s*:",
}

HARDCODED_SECRET_ASSIGNMENT_RULES = {
    "hardcoded_password": r"\bpassword\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{2,}[\"']?",
    "hardcoded_passwd": r"\bpasswd\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{2,}[\"']?",
    "hardcoded_token": r"\btoken\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
    "hardcoded_api_key": r"\bapi[_-]?key\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
    "hardcoded_access_key": r"\baccess[_-]?key\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
    "hardcoded_private_key": r"\bprivate[_-]?key\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
    "hardcoded_client_secret": r"\bclient[_-]?secret\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
    "hardcoded_secret_key": r"\bsecret[_-]?key\s*:\s*[\"']?[^\s\"'#][^\"'#\n]{5,}[\"']?",
}

SUSPICIOUS_LITERAL_VALUE_RULES = {
    "openai_key_pattern": r"\bsk-[A-Za-z0-9]{10,}\b",
    "aws_access_key_pattern": r"\bAKIA[0-9A-Z]{16}\b",
    "github_token_pattern": r"\bghp_[A-Za-z0-9]{20,}\b",
    "google_api_key_pattern": r"\bAIza[0-9A-Za-z\-_]{20,}\b",
    "long_base64_like_value": r"[:=]\s*[\"']?[A-Za-z0-9+/=]{32,}[\"']?",
}

def find_matches(content: str, rule_dict: dict) -> list[str]:
    matches = []
    for label, pattern in rule_dict.items():
        if re.search(pattern, content, flags=re.IGNORECASE):
            matches.append(label)
    return matches

def label_file(content: str):
    findings = []

    privilege_findings = find_matches(content, PRIVILEGE_RULES)
    safe_secret_findings = find_matches(content, SAFE_SECRET_REFERENCE_RULES)
    hardcoded_secret_findings = find_matches(content, HARDCODED_SECRET_ASSIGNMENT_RULES)
    suspicious_value_findings = find_matches(content, SUSPICIOUS_LITERAL_VALUE_RULES)

    findings.extend(privilege_findings)
    findings.extend(hardcoded_secret_findings)
    findings.extend(suspicious_value_findings)

    if privilege_findings:
        main_label = "privilege_exposure"
    elif hardcoded_secret_findings or suspicious_value_findings:
        main_label = "hardcoded_secret"
    else:
        main_label = "secure"

    return main_label, findings, safe_secret_findings

rows = []

for fname in os.listdir(SRC_DIR):
    path = os.path.join(SRC_DIR, fname)
    if not os.path.isfile(path):
        continue

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        main_label, findings, safe_secret_findings = label_file(content)

        rows.append({
            "file_name": fname,
            "label": main_label,
            "findings": ";".join(findings),
            "safe_secret_refs_detected": ";".join(safe_secret_findings),
        })
    except Exception as e:
        rows.append({
            "file_name": fname,
            "label": "error",
            "findings": str(e),
            "safe_secret_refs_detected": "",
        })

with open(OUT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["file_name", "label", "findings", "safe_secret_refs_detected"]
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"Saved labels to {OUT_CSV}")