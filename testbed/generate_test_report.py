"""
generate_test_report.py — Simulates a "perfect" scan result.

Reads the Gold Standard Report and serves it as a streaming response
via the backend API, or prints it to stdout with Hexstrike formatting.

Usage:
    python generate_test_report.py               # Print to terminal
    python generate_test_report.py --serve        # Send to backend API
    python generate_test_report.py --api-push     # Push to /api/analysis/report
"""

import sys
import os
import time
import argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPORT_PATH = os.path.join(SCRIPT_DIR, "GOLD_STANDARD_REPORT.md")

# ANSI colors for terminal output
C = {
    "RESET":    "\033[0m",
    "RED":      "\033[91m",
    "GREEN":    "\033[92m",
    "YELLOW":   "\033[93m",
    "BLUE":     "\033[94m",
    "PURPLE":   "\033[95m",
    "CYAN":     "\033[96m",
    "BOLD":     "\033[1m",
    "DIM":      "\033[2m",
}


def load_report() -> str:
    with open(REPORT_PATH, "r", encoding="utf-8") as f:
        return f.read()


def format_line(line: str) -> str:
    """Apply ANSI coloring based on content."""
    stripped = line.strip()

    if stripped.startswith("# ═"):
        return f"{C['PURPLE']}{C['BOLD']}{line}{C['RESET']}"
    if stripped.startswith("## "):
        return f"{C['CYAN']}{C['BOLD']}{line}{C['RESET']}"
    if stripped.startswith("### "):
        return f"{C['BLUE']}{C['BOLD']}{line}{C['RESET']}"
    if stripped.startswith("#### 🚨"):
        return f"{C['RED']}{C['BOLD']}{line}{C['RESET']}"
    if "CRITICAL" in stripped:
        return f"{C['RED']}{line}{C['RESET']}"
    if "HIGH" in stripped:
        return f"{C['YELLOW']}{line}{C['RESET']}"
    if "MEDIUM" in stripped:
        return f"{C['BLUE']}{line}{C['RESET']}"
    if "**Remediation:**" in stripped or "**Evidence:**" in stripped:
        return f"{C['GREEN']}{line}{C['RESET']}"
    if stripped.startswith("```"):
        return f"{C['DIM']}{line}{C['RESET']}"
    if stripped.startswith("|"):
        return f"{C['DIM']}{line}{C['RESET']}"
    if stripped.startswith("---"):
        return f"{C['DIM']}{line}{C['RESET']}"
    return line


def print_report_terminal():
    """Print the Gold Standard Report with color formatting and delay."""
    report = load_report()

    print(f"\n{C['PURPLE']}{C['BOLD']}[SENTINEL REPORT] Hexstrike Security Audit — Gold Standard{C['RESET']}")
    print(f"{C['DIM']}{'═' * 60}{C['RESET']}\n")

    for line in report.split("\n"):
        colored = format_line(line)
        print(colored)
        # Small delay for dramatic effect on findings
        if "SECURITY_ALERT" in line:
            time.sleep(0.15)
        elif line.strip().startswith("##"):
            time.sleep(0.1)
        else:
            time.sleep(0.02)

    print(f"\n{C['GREEN']}{C['BOLD']}[SENTINEL] Report complete. 22 findings.{C['RESET']}")
    print(f"{C['PURPLE']}[SENTINEL] Posture: CRITICAL — Immediate remediation required.{C['RESET']}\n")


def push_to_api():
    """Push the report lines to the backend API for UI display."""
    try:
        import httpx
    except ImportError:
        print("Install httpx: pip install httpx")
        sys.exit(1)

    report = load_report()
    lines = report.split("\n")

    # Format lines for the UI terminal
    formatted = []
    formatted.append("[SENTINEL REPORT] ═══ Hexstrike Security Audit — Gold Standard ═══")
    formatted.append("")

    for line in lines:
        stripped = line.strip()
        if not stripped:
            formatted.append("")
            continue

        if stripped.startswith("# ═"):
            continue  # Skip decorators
        elif stripped.startswith("#### 🚨"):
            # Extract alert
            formatted.append(f"[ALERT] {stripped.replace('#### ', '')}")
        elif stripped.startswith("## "):
            formatted.append(f"[SECTION] {stripped.replace('## ', '')}")
        elif stripped.startswith("### "):
            formatted.append(f"[SUBSEC] {stripped.replace('### ', '')}")
        elif stripped.startswith("**Remediation:**"):
            formatted.append("[FIX] Remediation:")
        elif stripped.startswith("**Evidence:**"):
            formatted.append("[EVIDENCE]")
        elif stripped.startswith("```"):
            continue
        elif stripped.startswith("|"):
            formatted.append(f"  {stripped}")
        elif stripped.startswith("- "):
            formatted.append(f"  {stripped}")
        else:
            formatted.append(f"  {stripped}")

    formatted.append("")
    formatted.append("[SENTINEL] Report complete. 22 findings. Posture: CRITICAL.")

    # POST to backend
    with httpx.Client() as client:
        resp = client.post(
            "http://localhost:8000/api/analysis/report",
            json={"lines": formatted},
            timeout=10,
        )
        if resp.status_code == 200:
            print(f"{C['GREEN']}Report pushed to UI terminal ({len(formatted)} lines).{C['RESET']}")
        else:
            print(f"{C['RED']}Failed: {resp.status_code} — {resp.text}{C['RESET']}")


def main():
    parser = argparse.ArgumentParser(description="Hexstrike Gold Standard Report Generator")
    parser.add_argument("--serve", action="store_true", help="Print formatted report")
    parser.add_argument("--api-push", action="store_true", help="Push report to UI via API")
    args = parser.parse_args()

    if args.api_push:
        push_to_api()
    else:
        print_report_terminal()


if __name__ == "__main__":
    main()
