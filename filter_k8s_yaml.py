import os
import shutil
import yaml

SRC_DIR = "all_yaml_raw"
DST_DIR = "k8s_yaml_only"

os.makedirs(DST_DIR, exist_ok=True)

def is_k8s_yaml(path: str) -> bool:
    try:
        with open(path, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        for doc in docs:
            if isinstance(doc, dict) and "apiVersion" in doc and "kind" in doc:
                return True
    except Exception:
        return False

    return False

count = 0
for fname in os.listdir(SRC_DIR):
    fpath = os.path.join(SRC_DIR, fname)
    if os.path.isfile(fpath) and is_k8s_yaml(fpath):
        shutil.copy2(fpath, os.path.join(DST_DIR, fname))
        count += 1

print(f"Copied {count} Kubernetes YAML files to {DST_DIR}")