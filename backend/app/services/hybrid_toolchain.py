import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

def run_hybrid_toolchain(target_dir: str):
    """
    Runs Syft, Grype, and KICS via Docker against the target directory,
    saving the output to .security_review/artifacts/raw_tools_output/.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        logger.error(f"Target directory {target_path} does not exist.")
        return False
        
    output_dir = target_path / ".security_review" / "artifacts" / "raw_tools_output"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"Running hybrid toolchain on {target_path}. Output dir: {output_dir}")
    
    # Run Syft
    syft_output = output_dir / "syft.json"
    syft_cmd = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/src",
        "anchore/syft:latest",
        "dir:/src", "-o", "json"
    ]
    logger.info("Running Syft...")
    try:
        with open(syft_output, "w", encoding="utf-8") as f:
            subprocess.run(syft_cmd, stdout=f, check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        logger.error(f"Syft failed: {e}")
    except subprocess.TimeoutExpired:
        logger.error("Syft timed out.")
        
    # Run Grype
    grype_output = output_dir / "grype.json"
    grype_cmd = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/src",
        "anchore/grype:latest",
        "dir:/src", "-o", "json"
    ]
    logger.info("Running Grype...")
    try:
        with open(grype_output, "w", encoding="utf-8") as f:
            subprocess.run(grype_cmd, stdout=f, check=True, timeout=300)
    except subprocess.CalledProcessError as e:
        logger.error(f"Grype failed: {e}")
    except subprocess.TimeoutExpired:
        logger.error("Grype timed out.")
        
    # Run KICS
    # KICS needs to write to an output directory mounted inside the container.
    # We mount target_path as /path, and output_dir as /output.
    kics_cmd = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/path",
        "-v", f"{output_dir}:/output",
        "checkmarx/kics:latest",
        "scan", "-p", "/path", "-o", "/output", "--report-formats", "json", "--output-name", "kics"
    ]
    logger.info("Running KICS...")
    try:
        subprocess.run(kics_cmd, check=False, timeout=600)  # KICS might return non-zero if issues found
    except subprocess.TimeoutExpired:
        logger.error("KICS timed out.")
        
    logger.info(f"Hybrid toolchain execution completed. Artifacts saved in {output_dir}")
    return True

if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) > 1:
        run_hybrid_toolchain(sys.argv[1])
    else:
        print("Usage: python hybrid_toolchain.py <target_directory>")
