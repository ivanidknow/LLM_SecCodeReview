import os
import glob
import re

TARGET_DIR = r"c:\Users\user\Desktop\security review\.security_review\guidelines\deep_scan\logic_review"

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
SCENARIO_OF_ATTACK: [Must not be empty. Describe how an attacker manipulates business states step-by-step (e.g. 1. Login as User A -> 2. Change user_id in request to User B -> 3. Access private data without AuthZ check)]
</OUTPUT_SPEC>"""
    
    content = re.sub(r"<OUTPUT_SPEC>.*?</OUTPUT_SPEC>", new_output_spec, content, flags=re.DOTALL)

    if "<EXECUTION_PIPELINE>" in content:
        if "ANTI_HALLUCINATION_GUARD" not in content:
            rules = "\n   - ANTI_HALLUCINATION_GUARD: If a function/endpoint is empty or has a TODO/Placeholder, DO NOT trigger high-impact logic vulnerabilities like Race Conditions or Discount Stacking unless there is actual code implementing that logic. If the code is missing, report it only once as 'Incomplete Implementation' under broken_access_control.protocol."
            rules += "\n   - ARCHITECTURE_SYNC: Use data from identity_model.protocol and authentication_strategy.protocol to verify if the found bypass contradicts the established architecture."
            content = re.sub(r"(</EXECUTION_PIPELINE>)", lambda m: rules + "\n" + m.group(1), content)

    if "<CONTEXT_MAP>" in content:
        if "identity_model.protocol" not in content:
            context_additions = "\n[IDENTITY_MODEL]    <- {from: identity_model.protocol, scope: \"AUTH_CONTEXT\"}\n[AUTHENTICATION]    <- {from: authentication_strategy.protocol, scope: \"AUTH_MECHANISM\"}\n"
            content = re.sub(r"(</CONTEXT_MAP>)", lambda m: context_additions + m.group(1), content)
    else:
        # If no CONTEXT_MAP exists, add it before ASSERTIONS or EXECUTION_PIPELINE
        context_block = """<CONTEXT_MAP>
[IDENTITY_MODEL]    <- {from: identity_model.protocol, scope: "AUTH_CONTEXT"}
[AUTHENTICATION]    <- {from: authentication_strategy.protocol, scope: "AUTH_MECHANISM"}
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
    "IAM": 50,
    "DATA_SAFETY": 10,
    "LOGIC_INTEGRITY": 40,
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
