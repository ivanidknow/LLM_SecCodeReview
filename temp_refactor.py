import os
import glob
import re

TARGET_DIR = r"c:\Users\user\Desktop\security review\.security_review\guidelines\deep_scan\taint_analysis"

def process_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # Get the protocol ID
    id_match = re.search(r"@ID:\s*(.*?)\n", content)
    protocol_id = id_match.group(1).strip() if id_match else "UNKNOWN"

    # Replace OUTPUT_SPEC
    new_output_spec = f"""<OUTPUT_SPEC>
To report a vulnerability, strictly use the following format:

🚨 FINDING [{protocol_id}]
FILE: [FilePath]
LINE: [LineNumber]
CODE: [CodeSnippet]
DESCRIPTION: [Description of the issue]
SCENARIO_OF_ATTACK: [Must not be empty. Describe step-by-step: External Input -> Transformation -> Sensitive Sink]
</OUTPUT_SPEC>"""
    
    content = re.sub(r"<OUTPUT_SPEC>.*?</OUTPUT_SPEC>", new_output_spec, content, flags=re.DOTALL)

    # Append Taint Specifics to EXECUTION_PIPELINE if not exists
    if "<EXECUTION_PIPELINE>" in content:
        if "validation_chokepoints.protocol" not in content:
            taint_rule = "\n   - TAINT SPECIFICS: Check for Sanitizers and Validators from validation_chokepoints.protocol. If a sanitizer is found, downgrade or skip the finding. Focus on full Reachability analysis."
            content = re.sub(r"(</EXECUTION_PIPELINE>)", lambda m: taint_rule + "\n" + m.group(1), content)

    # Replace @ANALYTICS_DATA if not exists, right before </DFD_MODELING_V3>
    if "@ANALYTICS_DATA" not in content:
        analytics = """
@ANALYTICS_DATA: {
  "domains": {
    "IAM": 0,
    "DATA_SAFETY": 80,
    "LOGIC_INTEGRITY": 50,
    "INFRA": 0,
    "COMPLIANCE": 0
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
