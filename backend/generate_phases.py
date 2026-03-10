import os
import json
import glob

guidelines_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".security_review", "guidelines"))
protocol_files = glob.glob(os.path.join(guidelines_dir, "**", "*.protocol"), recursive=True)

# Define 6 phases
phases = {
    "1": {"name": "Architecture & IAM", "protocols": []},
    "2": {"name": "Data Flow & Taint", "protocols": []},
    "3": {"name": "Business Logic & Fraud", "protocols": []},
    "4": {"name": "Negative Constraints & Race", "protocols": []},
    "5": {"name": "Infrastructure & IaC", "protocols": []},
    "6": {"name": "Compliance & License", "protocols": []}
}

for pf in protocol_files:
    # Example filename: 01_auth_bypass.protocol -> auth_bypass
    basename = os.path.basename(pf).replace('.protocol', '')
    # Strip leading numbers like 01_
    parts = basename.split('_', 1)
    if len(parts) == 2 and parts[0].isdigit():
        pid = parts[1]
    else:
        pid = basename
        
    content = ""
    with open(pf, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read().lower()
        
    # very simple heuristic for categorization
    if "iam" in content or "auth" in content or "identity" in content or "topology" in content or "access" in content or "rbac" in content:
        phases["1"]["protocols"].append(pid)
    elif "data flow" in content or "taint" in content or "sink" in content or "injection" in content or "xss" in content or "sqli" in content:
        phases["2"]["protocols"].append(pid)
    elif "fraud" in content or "business" in content or "price" in content or "tampering" in content or "ato" in content or "logic" in content:
        phases["3"]["protocols"].append(pid)
    elif "race" in content or "toctou" in content or "memory" in content or "state" in content or "constraint" in content or "leak" in content:
        phases["4"]["protocols"].append(pid)
    elif "iac" in content or "infra" in content or "k8s" in content or "terraform" in content or "docker" in content or "secret" in content or "cloud" in content:
        phases["5"]["protocols"].append(pid)
    elif "compliance" in content or "license" in content or "copyleft" in content or "sbom" in content or "patent" in content:
        phases["6"]["protocols"].append(pid)
    else:
        # Default fallback
        if "web" in pf or "api" in pf:
            phases["2"]["protocols"].append(pid)
        else:
            phases["1"]["protocols"].append(pid)

output_file = os.path.join(os.path.dirname(__file__), "app", "api", "sub_phase_definitions.json")
with open(output_file, "w") as f:
    json.dump(phases, f, indent=4)
    
print(f"Generated {output_file} with {sum(len(p['protocols']) for p in phases.values())} protocols.")
