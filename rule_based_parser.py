import os
import json
import yaml

# Rule-based security parser for kubernetes ymal manifests
# Reads the content of k8s_yaml_only 
# Writes the finding to security_report.json

# Directory output of filter_k8s_yml
INPUT_DIR = "k8s_yaml_only"
# Output where JSON security report written
OUTPUT_FILE = "security_report.json"

DOCKER_SOCK_PATH = "/var/run/docker.sock"

# All the rules id that parser checks
RULES_CHECKED = [
    "privileged",
    "hostNetwork",
    "hostPID",
    "dockerSockMount",
    "allowPrivilegeEscalation",
]


def get_pod_specs(doc):
    """
    Extract pod specs from available Kubernetes resource document.
    Handles: Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, and CronJob.
    """
    kind = doc.get("kind", "")
    spec = doc.get("spec") or {}

    if kind == "Pod":
        return [spec]

    if kind in ("Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"):
        pod_spec = spec.get("template", {}).get("spec")
        return [pod_spec] if pod_spec else []

    if kind == "CronJob":
        pod_spec = (
            spec.get("jobTemplate", {})
            .get("spec", {})
            .get("template", {})
            .get("spec")
        )
        return [pod_spec] if pod_spec else []

    return []


def check_pod_spec(pod_spec, issues, location):
    """Check pod level security fields and delegate to container checks."""

    if pod_spec.get("hostNetwork") is True:
        issues.append({
            "rule": "hostNetwork",
            "severity": "HIGH",
            "location": location,
            "detail": "hostNetwork: true — pod shares the host network namespace, "
                      "exposing all host network interfaces and services.",
        })

    if pod_spec.get("hostPID") is True:
        issues.append({
            "rule": "hostPID",
            "severity": "HIGH",
            "location": location,
            "detail": "hostPID: true — pod can see and signal all processes on the host.",
        })

    # Check volumes for docker socket host path
    for vol in pod_spec.get("volumes") or []:
        host_path = vol.get("hostPath") or {}
        if isinstance(host_path, dict) and DOCKER_SOCK_PATH in host_path.get("path", ""):
            issues.append({
                "rule": "dockerSockMount",
                "severity": "CRITICAL",
                "location": f"{location}.volumes[{vol.get('name', '?')}]",
                "detail": f"Volume exposes {DOCKER_SOCK_PATH} — grants full Docker daemon "
                          "access, enabling container escape.",
            })

    # Check containers and initContainers
    for section in ("containers", "initContainers"):
        for container in pod_spec.get(section) or []:
            if not isinstance(container, dict):
                continue
            cname = container.get("name", "unknown")
            check_container(container, issues, f"{location}.{section}[{cname}]")


def check_container(container, issues, location):
    """Check container level security context and volume mount """

    sec_ctx = container.get("securityContext") or {}

    if sec_ctx.get("privileged") is True:
        issues.append({
            "rule": "privileged",
            "severity": "CRITICAL",
            "location": f"{location}.securityContext",
            "detail": "privileged: true — container runs with full host root privileges, "
                      "equivalent to running as root on the node.",
        })

    if sec_ctx.get("allowPrivilegeEscalation") is True:
        issues.append({
            "rule": "allowPrivilegeEscalation",
            "severity": "HIGH",
            "location": f"{location}.securityContext",
            "detail": "allowPrivilegeEscalation: true — process inside the container can "
                      "gain more privileges than its parent process.",
        })

    # Check volumeMounts for docker socket
    for vm in container.get("volumeMounts") or []:
        if DOCKER_SOCK_PATH in (vm.get("mountPath") or ""):
            issues.append({
                "rule": "dockerSockMount",
                "severity": "CRITICAL",
                "location": f"{location}.volumeMounts[{vm.get('name', '?')}]",
                "detail": f"Container mounts {DOCKER_SOCK_PATH} — grants direct access to "
                          "the Docker daemon, allowing container escape.",
            })


def analyze_file(filepath):
    """
    Parse a YAML file either single or multi-document; and return all detected issues.
    Returns a list of issue dicts and empty list if no issues are found.
    """
    issues = []

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))
    except Exception as e:
        return [{"rule": "parse_error", "severity": "ERROR", "location": filepath, "detail": str(e)}]

    for i, doc in enumerate(docs):
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "unknown")
        metadata = doc.get("metadata") or {}
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        # location prefix
        loc = f"{kind}/{namespace}/{name}"
        if len(docs) > 1:
            loc = f"doc[{i}]:{loc}"

        pod_specs = get_pod_specs(doc)
        for pod_spec in pod_specs:
            check_pod_spec(pod_spec, issues, loc)

    return issues


def main():
    if not os.path.isdir(INPUT_DIR):
        print(
            f"[ERROR] Input directory '{INPUT_DIR}' not found.\n"
            "        Run filter_k8s_yaml.py first to populate it."
        )
        return

    report = {}
    total_files = 0
    flagged_files = 0
    total_issues = 0

    for fname in sorted(os.listdir(INPUT_DIR)):
        fpath = os.path.join(INPUT_DIR, fname)
        if not os.path.isfile(fpath):
            continue

        total_files += 1
        issues = analyze_file(fpath)

        if issues:
            flagged_files += 1
            total_issues += len(issues)
            report[fname] = {
                "issue_count": len(issues),
                "issues": issues,
            }

    output = {
        "summary": {
            "total_files_scanned": total_files,
            "flagged_files": flagged_files,
            "clean_files": total_files - flagged_files,
            "total_issues": total_issues,
            "rules_checked": RULES_CHECKED,
        },
        "findings": report,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print(f"Scan complete.")
    print(f"  Total Files scanned : {total_files}")
    print(f"  Total Files flagged : {flagged_files}")
    print(f"  Total issues  : {total_issues}")
    print(f"  Report saved  : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
