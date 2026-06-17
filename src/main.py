import os
import sys
import json
import subprocess
import shutil
from git import Repo

# Import our custom modules
from parser import SemgrepParser
from triage_agent import LLMTriageAgent

# Define paths dynamically based on current working directory
WORKSPACE = os.getcwd()
CLONED_DIR = os.path.join(WORKSPACE, "tmp_target_repo")
OUTPUT_JSON = os.path.join(WORKSPACE, "semgrep_results.json")
FINAL_REPORT = os.path.join(WORKSPACE, "final_security_report.json")

def clean_up():
    if os.path.exists(CLONED_DIR):
        print(f"[*] Cleaning up previous repository at {CLONED_DIR}...")
        try:
            import stat
            def remove_readonly(func, path, _):
                os.chmod(path, stat.S_IWRITE)
                func(path)
            shutil.rmtree(CLONED_DIR, onerror=remove_readonly)
        except Exception as e:
            print(f"[-] Failed to clean up: {e}")
    if os.path.exists(OUTPUT_JSON):
        os.remove(OUTPUT_JSON)

def clone_repository(repo_url):
    try:
        print(f"[*] Cloning repository from: {repo_url}...")
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        Repo.clone_from(repo_url, CLONED_DIR, env=env)
        print("[+] Repository cloned successfully.")
        return CLONED_DIR
    except Exception as e:
        print(f"[-] Deployment failure during git clone operation: {e}")
        sys.exit(1)

def run_semgrep_scan(target_dir):
    print(f"[*] Launching Semgrep static application security testing (SAST) on {target_dir}...")
    command = [ 
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        f"--output={OUTPUT_JSON}",
        target_dir
    ]
    try:
        # Use shell=True on Windows to resolve the semgrep command if installed via pip
        result = subprocess.run(command, capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
        if os.path.exists(OUTPUT_JSON):
            print(f"[+] Scan completed. Artifacts saved to {OUTPUT_JSON}")
        else:
            print("[-] Critical Error: Semgrep execution finished without generating artifacts.")
            print(f"Pipeline Stderr Log: {result.stderr}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Subprocess orchestration failed during Semgrep invocation: {e}")
        sys.exit(1)

def process_results():
    print("[*] Parsing Semgrep JSON findings...")
    parser = SemgrepParser(OUTPUT_JSON)
    findings = parser.parse_findings()
    
    if not findings:
        print("[+] No vulnerabilities found. The codebase is clean!")
        return

    print(f"[*] Total Initial Findings: {len(findings)}")
    print("[*] Initializing LLM Triage Agent (Gemini 3.1 Flash)...")
    
    # We use the fastest/best free cloud model we found during our benchmarking
    agent = LLMTriageAgent(model_name="gemini/gemini-3.1-flash-lite")
    
    report_data = []
    
    for i, finding in enumerate(findings, 1):
        rule_id = finding.get('rule_id', 'Unknown')
        file_path = finding.get('target_file', 'Unknown')
        print(f"\n[{i}/{len(findings)}] Triaging {rule_id} in {file_path}")
        
        # 1. Triage the finding
        triage_decision = agent.analyze_finding(finding)
        classification = triage_decision.get("classification", "ERROR")
        justification = triage_decision.get("justification", "")
        
        finding_report = {
            "finding": rule_id,
            "file": file_path,
            "classification": classification,
            "justification": justification,
            "patch": None
        }
        
        if classification == "TP":
            print("      [!] TRUE POSITIVE identified. Generating patch...")
            # 2. Remediate if True Positive
            patch_data = agent.generate_patch(finding)
            finding_report["patch"] = patch_data
            
            patch_strategy = patch_data.get('patch_strategy', '')
            if patch_strategy:
                print(f"      [+] Patch Strategy: {patch_strategy}")
        elif classification == "FP":
            print("      [v] FALSE POSITIVE. Discarding alert.")
        else:
            print(f"      [?] UNKNOWN CLASSIFICATION. Error: {justification}")
            
        report_data.append(finding_report)
        
    # Save the final report
    with open(FINAL_REPORT, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=4)
        
    print(f"\n[+] Production scan complete! Final security report saved to {FINAL_REPORT}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[-] Execution Error. Usage: python src/main.py <GITHUB_URL_OR_LOCAL_DIR>")
        sys.exit(1)

    target_input = sys.argv[1]
    clean_up()
    
    target_directory = target_input
    # Check if input is a URL or a local directory
    if target_input.startswith("http://") or target_input.startswith("https://"):
        target_directory = clone_repository(target_input)
    elif not os.path.exists(target_input):
        print(f"[-] Error: Local path '{target_input}' does not exist.")
        sys.exit(1)
        
    run_semgrep_scan(target_directory)
    process_results()
