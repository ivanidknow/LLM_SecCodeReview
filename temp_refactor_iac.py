import os
import glob
import re

TARGET_DIR = r"c:\Users\user\Desktop\security review\.security_review\guidelines\deep_scan\iac_review"

def process_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    id_match = re.search(r"@ID:\s*(.*?)\n", content)
    protocol_id = id_match.group(1).strip() if id_match else "UNKNOWN"

    new_output_spec = f"""<OUTPUT_SPEC>
To report a vulnerability, strictly use the following format:

🚨 FINDING [{protocol_id}]
FILE: [FilePath]
LINE: [LineNumber]
CODE: [CodeSnippet]
DESCRIPTION: [Description of the issue]
SCENARIO_OF_ATTACK: [Must not be empty. Describe how a misconfiguration in infrastructure impacts the application security. Example: 1. Container runs as root -> 2. Attacker exploits RCE in app -> 3. Attacker gains full host access due to lack of isolation.]
</OUTPUT_SPEC>"""
    
    content = re.sub(r"<OUTPUT_SPEC>.*?</OUTPUT_SPEC>", new_output_spec, content, flags=re.DOTALL)

    if "<EXECUTION_PIPELINE>" in content:
        if "IAC_SPECIFICS" not in content:
            rules = "\n   - IAC_SPECIFICS: For Dockerfile verify least privilege, base image provenance, secret leakage in layers. For Kubernetes verify RBAC, Network Policies, Security Contexts. For Terraform/Cloud verify Public exposure, IAM over-privileging, encryption at rest."
            rules += "\n   - ENV_AWARENESS: Use data from network_infra.protocol to distinguish between Production and Development hardening levels."
            content = re.sub(r"(</EXECUTION_PIPELINE>)", lambda m: rules + "\n" + m.group(1), content)

    if "<CONTEXT_MAP>" in content:
        if "network_infra.protocol" not in content:
            context_additions = "\n[NETWORK_INFRA]    <- {from: network_infra.protocol, scope: \"ENV_TOPOLOGY\"}\n"
            content = re.sub(r"(</CONTEXT_MAP>)", lambda m: context_additions + m.group(1), content)
    else:
        context_block = """<CONTEXT_MAP>
[NETWORK_INFRA]    <- {from: network_infra.protocol, scope: "ENV_TOPOLOGY"}
</CONTEXT_MAP>

"""
        if "<ASSERTIONS>" in content:
            content = content.replace("<ASSERTIONS>", context_block + "<ASSERTIONS>")
        elif "<EXECUTION_PIPELINE>" in content:
            content = content.replace("<EXECUTION_PIPELINE>", context_block + "<EXECUTION_PIPELINE>")

    if "@ANALYTICS_DATA" not in content:
        analytics = """
@ANALYTICS_DATA: {
  "domains": {
    "IAM": 0,
    "DATA_SAFETY": 50,
    "LOGIC_INTEGRITY": 0,
    "INFRA": 90,
    "COMPLIANCE": 10
  }
}
"""
        content = content.replace("</DFD_MODELING_V3>", analytics + "</DFD_MODELING_V3>")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Refactored: {filepath}")

protocol_files = glob.glob(os.path.join(TARGET_DIR, "**", "*.protocol"), recursive=True)
for f in protocol_files:
    process_file(f)

print(f"Total processed: {len(protocol_files)}")
