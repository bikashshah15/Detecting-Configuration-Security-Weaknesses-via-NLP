import json

STRUCTURAL_REPORT = "security_report.json"
REGEX_REPORT = "rule_based_report.json"
OUTPUT_FILE = "consolidated_report.json"

SEVERITY_RANK = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "NONE": 0}


def derive_label_from_structural(issues):
    """Derive a predicted label from structural issues (security_report.json)."""
    if issues:
        return "privilege_exposure"
    return "secure"


def resolve_final_label(label_structural, label_regex):
    """Merge two labels using priority: privilege_exposure > hardcoded_secret > secure."""
    priority = {"privilege_exposure": 2, "hardcoded_secret": 1, "secure": 0}
    if priority.get(label_structural, 0) >= priority.get(label_regex, 0):
        return label_structural
    return label_regex


def resolve_final_severity(structural_issues, hardcoded_secret_findings):
    """
    Determine file-level severity from all findings.
    CRITICAL > HIGH > MEDIUM > NONE
    """
    highest = "NONE"

    for issue in structural_issues:
        sev = issue.get("severity", "NONE")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK[highest]:
            highest = sev

    if highest == "NONE" and hardcoded_secret_findings:
        highest = "MEDIUM"

    return highest


def load_structural_report(path):
    """
    Load security_report.json.
    Returns a dict keyed by file_name -> list of issues.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = data.get("findings", {})
    result = {}
    for fname, entry in findings.items():
        result[fname] = entry.get("issues", [])
    return result


def load_regex_report(path):
    """
    Load rule_based_report.json.
    Returns a dict keyed by file_name -> entry dict.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = {}
    for entry in data:
        fname = entry.get("file_name")
        if fname:
            result[fname] = entry
    return result


def build_consolidated_record(fname, structural_issues, regex_entry):
    """Build a single merged record for one file."""

    label_structural = derive_label_from_structural(structural_issues)

    label_regex = "secure"
    privilege_findings = []
    hardcoded_secret_findings = []
    safe_secret_references = []
    parse_error = None

    if regex_entry:
        label_regex = regex_entry.get("predicted_label", "secure")
        parse_error = regex_entry.get("parse_error")
        findings = regex_entry.get("findings", {})
        privilege_findings = findings.get("privilege_findings", [])
        hardcoded_secret_findings = findings.get("hardcoded_secret_findings", [])
        safe_secret_references = findings.get("safe_secret_references", [])

    final_label = resolve_final_label(label_structural, label_regex)
    final_severity = resolve_final_severity(structural_issues, hardcoded_secret_findings)

    return {
        "file_name": fname,
        "final_label": final_label,
        "final_severity": final_severity,
        "label_from_structural": label_structural,
        "label_from_regex": label_regex,
        "parse_error": parse_error,
        "structural_issues": structural_issues,
        "privilege_findings": privilege_findings,
        "hardcoded_secret_findings": hardcoded_secret_findings,
        "safe_secret_references": safe_secret_references,
    }


def build_summary(records):
    """Build aggregate summary stats from all merged records."""
    total = len(records)
    by_label = {"privilege_exposure": 0, "hardcoded_secret": 0, "secure": 0}
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "NONE": 0}
    total_structural_issues = 0
    total_hardcoded_secrets = 0
    flagged = 0

    for rec in records:
        label = rec["final_label"]
        sev = rec["final_severity"]
        by_label[label] = by_label.get(label, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        total_structural_issues += len(rec["structural_issues"])
        total_hardcoded_secrets += len(rec["hardcoded_secret_findings"])
        if label != "secure":
            flagged += 1

    return {
        "total_files": total,
        "flagged_files": flagged,
        "clean_files": total - flagged,
        "by_label": by_label,
        "by_severity": by_severity,
        "total_structural_issues": total_structural_issues,
        "total_hardcoded_secret_findings": total_hardcoded_secrets,
    }


def main():
    print(f"Loading {STRUCTURAL_REPORT} ...")
    structural = load_structural_report(STRUCTURAL_REPORT)

    print(f"Loading {REGEX_REPORT} ...")
    regex = load_regex_report(REGEX_REPORT)

    all_files = sorted(set(structural.keys()) | set(regex.keys()))
    print(f"Total unique files across both reports: {len(all_files)}")

    records = []
    for fname in all_files:
        structural_issues = structural.get(fname, [])
        regex_entry = regex.get(fname)
        record = build_consolidated_record(fname, structural_issues, regex_entry)
        records.append(record)

    summary = build_summary(records)

    output = {
        "summary": summary,
        "findings": records,
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nConsolidation complete.")
    print(f"  Total files      : {summary['total_files']}")
    print(f"  Flagged files    : {summary['flagged_files']}")
    print(f"  Clean files      : {summary['clean_files']}")
    print(f"  By label         : {summary['by_label']}")
    print(f"  By severity      : {summary['by_severity']}")
    print(f"  Structural issues: {summary['total_structural_issues']}")
    print(f"  Hardcoded secrets: {summary['total_hardcoded_secret_findings']}")
    print(f"  Report saved     : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
