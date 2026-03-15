import os
import glob
import re

directories = [
    r"c:\Users\user\Desktop\security review\.security_review\guidelines\deep_scan\discovery_driven_sast",
    r"c:\Users\user\Desktop\security review\.security_review\guidelines\deep_scan\iac_review"
]

def process_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Determine if it's SCA or IaC to specify the tool
    # Let's just use generic [Tool_Name] or specific if possible.
    # The prompt asked for: "DESCRIPTION: [Tool_Name] found [Vulnerability_ID]. AI Analysis confirmed that the vulnerable path is active in the current code flow via [Function_Name]."
    
    # 1. Update EXECUTION_PIPELINE
    if "<EXECUTION_PIPELINE>" in content:
        if "HYBRID_ANALYSIS" not in content:
            hybrid_rules = "\n   - HYBRID_ANALYSIS: Read JSON artifacts (syft.json, grype.json, kics.json) from .security_review/artifacts/raw_tools_output/. Treat these results as 'Hard Evidence'. Perform AI Reachability Analysis to verify if the vulnerable component is reachable from the code. If confirmed, elevate the finding status to BLOCKER."
            content = re.sub(r"(</EXECUTION_PIPELINE>)", lambda m: hybrid_rules + "\n" + m.group(1), content)

    # 2. Update DESCRIPTION format in OUTPUT_SPEC
    # We'll regex replace DESCRIPTION: .* with the new description format
    if "DESCRIPTION: " in content:
        new_desc = "DESCRIPTION: [Tool_Name] found [Vulnerability_ID]. AI Analysis confirmed that the vulnerable path is active in the current code flow via [Function_Name]."
        # Find the DESCRIPTION line and replace it
        content = re.sub(r"DESCRIPTION:\s*.*", new_desc, content)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Refactored: {filepath}")

for d in directories:
    protocol_files = glob.glob(os.path.join(d, "**", "*.protocol"), recursive=True)
    for f in protocol_files:
        process_file(f)

print("Finished Hybrid Protocol Context Mapping.")
