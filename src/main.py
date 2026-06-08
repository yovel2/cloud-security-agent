import os
import sys
import subprocess
import shutil
from git import Repo
from evaluator import run_evaluation


# Define volatile container paths for stateless execution
TARGET_DIR = "/tmp/target_repo"
OUTPUT_JSON = "/tmp/semgrep_results.json"


def clean_up():
    """
    Ensures a stateless execution environment by removing residual files
    and directories from prior pipeline runs.
    """
    if os.path.exists(TARGET_DIR):
        print(f"[*] Cleaning up previous repository at {TARGET_DIR}...")
        shutil.rmtree(TARGET_DIR)
    if os.path.exists(OUTPUT_JSON):
        os.remove(OUTPUT_JSON)


def clone_repository(repo_url):
    """
    Dynamically clones the target GitHub repository into the local container file system.
    Includes a configuration to prevent interactive credential prompts.
    """
    try:
        print(f"[*] Cloning repository from: {repo_url}...")

        # This environment variable prevents Git from hanging on credential prompts
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"

        Repo.clone_from(repo_url, TARGET_DIR, env=env)
        print("[+] Repository cloned successfully.")
    except Exception as e:
        print(f"[-] Deployment failure during git clone operation: {e}")
        # Hint: If this fails on a private repo, you'll need to use a Personal Access Token (PAT)
        sys.exit(1)

def run_semgrep_scan():
    """
    Executes the Semgrep static analysis engine over the ingested codebase
    and outputs the raw vulnerabilities report in structured JSON format.
    """
    print("[*] Launching Semgrep static application security testing (SAST)...")

    # Utilizing auto-configuration to fetch optimal rulesets for AppSec and IaC/Cloud misconfigurations.
    # The JSON format is required for structured object mapping by the LLM ingestion layers.
    command = [ 
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        f"--output={OUTPUT_JSON}",
        TARGET_DIR
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True)

        if os.path.exists(OUTPUT_JSON):
            print(f"[+] Scan orchestration completed. Artifacts saved to {OUTPUT_JSON}")
        else:
            print("[-] Critical Error: Semgrep execution finished without generating artifacts.")
            print(f"Pipeline Stderr Log: {result.stderr}")

    except Exception as e:
        print(f"[-] Subprocess orchestration failed during Semgrep invocation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Execution Error. Usage: python main.py <GITHUB_REPOSITORY_URL>")
        sys.exit(1)

    target_github_url = sys.argv[1]

    clean_up()
    clone_repository(target_github_url)
    run_semgrep_scan()

    # Run the benchmarking suite instead of the hardcoded Gemini run
    run_evaluation()