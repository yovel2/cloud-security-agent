import os
import sys
import json
import subprocess
import shutil
from git import Repo
from parser import SemgrepParser
from triage_agent import LLMTriageAgent
from litellm import completion

# Define volatile container paths for stateless execution
TARGET_DIR = "/tmp/target_repo"
OUTPUT_JSON = "/tmp/semgrep_results.json"

# --- MULTI-AGENT PIPELINE CONFIGURATION ---
TRIAGE_MODEL = "gemini/gemini-3.1-flash-lite"  # Agent 1: Fast filtering (Google) - YOUR ORIGINAL
IAC_PATCH_MODEL = "groq/llama-3.3-70b-versatile"  # Agent 2A: Deep code remediation for IaC (Meta) - YOUR ORIGINAL
APPSEC_PATCH_MODEL = "gemini/gemini-3.1-flash-lite"  # Agent 2B: Application Code Expert (Yair's Winner)
REPORT_MODEL = "cohere/command-r-plus-08-2024"  # Agent 3: Executive Reporting (Cohere)


def clean_up():
    """Ensures a stateless execution environment by removing residual files."""
    if os.path.exists(TARGET_DIR):
        print(f"[*] Cleaning up previous repository at {TARGET_DIR}...")
        shutil.rmtree(TARGET_DIR)
    if os.path.exists(OUTPUT_JSON):
        os.remove(OUTPUT_JSON)


def clone_repository(repo_url):
    """Dynamically clones the target GitHub repository."""
    try:
        print(f"[*] Cloning repository from: {repo_url}...")
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        Repo.clone_from(repo_url, TARGET_DIR, env=env)
        print("[+] Repository cloned successfully.")
    except Exception as e:
        print(f"[-] Deployment failure during git clone operation: {e}")
        sys.exit(1)


def run_semgrep_scan():
    """Executes the Semgrep static analysis engine for BOTH AppSec and IaC."""
    print("[*] Launching Semgrep SAST (AppSec) & IaC Scanning...")
    command = [
        "semgrep", "scan",
        "--config=auto",
        "--config=p/python",  # AppSec (Yair)
        "--config=p/owasp-top-ten",  # AppSec (Yair)
        "--config=p/docker",  # IaC (You)
        "--config=p/terraform",  # IaC (You)
        "--json", f"--output={OUTPUT_JSON}", TARGET_DIR
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
        if os.path.exists(OUTPUT_JSON):
            print(f"[+] Scan orchestration completed. Artifacts saved to {OUTPUT_JSON}")
        else:
            print("[-] Critical Error: Semgrep execution finished without generating artifacts.")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Subprocess orchestration failed: {e}")
        sys.exit(1)


def generate_final_report(confirmed_vulnerabilities, target_repo):
    """
    Agent 3 (Cohere): Generates the final Executive Security Report.
    """
    print(f"\n[*] Activating Agent 3 ({REPORT_MODEL}) for Final Report Generation...")

    system_prompt = """
    You are a Lead Cloud Security Architect. 
    You are receiving a JSON array of CONFIRMED vulnerabilities from a target repository.
    These issues span both Infrastructure as Code (IaC) and Application Security (AppSec).

    Your task is to generate a highly professional, well-structured 'Unified Executive Security & Remediation Report' in Markdown.

    Structure the report as follows:
    1. **Executive Summary:** A brief overview of the scan results.
    2. **Vulnerability Highlights:** A bulleted list of the most critical issues found.
    3. **Detailed Findings & Remediation:** For EACH vulnerability, create a clear section that includes:
       - Domain (AppSec or IaC) & Rule ID
       - File Location
       - Security Analysis (Why it's dangerous)
       - Patch Strategy (How it was fixed)
       - Code Block showing the Original Code and the Fixed Code.

    Tone: Professional, authoritative, and actionable. Do NOT use markdown code blocks (```markdown) to wrap your entire response, just output the raw markdown text.
    """

    user_prompt = f"Target Repository: {target_repo}\n\nConfirmed Vulnerabilities Data:\n{json.dumps(confirmed_vulnerabilities, indent=2)}"

    try:
        response = completion(
            model=REPORT_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            timeout=600
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"# Error Generating Final Report\n\nAgent 3 (Cohere) failed with error: {e}"


def run_multi_agent_pipeline(repo_url):
    """
    Orchestrates the Smart-Routing Multi-Agent AI Pipeline.
    """
    print("\n" + "=" * 60)
    print("   🚀 INITIATING HYDROAD UNIFIED SECURITY PIPELINE (APPSEC + IAC)")
    print("=" * 60)

    # Step 1: Parse Semgrep Results
    parser = SemgrepParser(OUTPUT_JSON)
    all_findings = parser.parse_findings()
    print(f"[*] Raw Semgrep artifacts extracted: {len(all_findings)}")

    if not all_findings:
        print("[+] No vulnerabilities detected by Semgrep. Exiting pipeline.")
        return

    # Initialize Agents
    triage_agent = LLMTriageAgent(model_name=TRIAGE_MODEL)
    iac_patch_agent = LLMTriageAgent(model_name=IAC_PATCH_MODEL)
    appsec_patch_agent = LLMTriageAgent(model_name=APPSEC_PATCH_MODEL)

    confirmed_findings = []

    # Step 2: Agent 1 (Triage) & Agent 2 (Smart Patching)
    for idx, finding in enumerate(all_findings):
        rule_id = finding['rule_id'].lower()
        print(f"\n[*] Processing Finding {idx + 1}/{len(all_findings)}: {finding['rule_id']}")

        # --- AGENT 1: TRIAGE ---
        print(f"    -> Agent 1 ({TRIAGE_MODEL}) is analyzing for False Positives...")
        triage_result = triage_agent.analyze_finding(finding)
        classification = triage_result.get("classification", "ERROR")

        if classification == "TP":
            finding["reasoning"] = triage_result.get("justification", "No reasoning provided.")

            # --- SMART ROUTER: Domain Classification ---
            iac_keywords = ["docker", "terraform", "kubernetes", "yaml", "cloudformation", "helm"]
            is_iac = any(keyword in rule_id or keyword in finding['target_file'].lower() for keyword in iac_keywords)

            if is_iac:
                domain = "IaC"
                active_patch_agent = iac_patch_agent
                model_name = IAC_PATCH_MODEL
            else:
                domain = "AppSec"
                active_patch_agent = appsec_patch_agent
                model_name = APPSEC_PATCH_MODEL

            print(f"    [+] CONFIRMED TRUE POSITIVE ({domain}). Routing to {model_name}...")

            # --- AGENT 2: DOMAIN-SPECIFIC REMEDIATION ---
            patch_result = active_patch_agent.generate_patch(finding)

            finding["domain"] = domain
            finding["patch_strategy"] = patch_result.get("patch_strategy", "")
            finding["original_code"] = patch_result.get("original_code", "")  # Based on Yair's JSON Schema
            finding["fixed_code"] = patch_result.get("fixed_code", "")
            confirmed_findings.append(finding)
        else:
            print(f"    [-] Dismissed as {classification}. Skipping patch generation.")

    # Step 3: Agent 3 (Reporting)
    print("\n" + "=" * 60)
    print(f"[*] Pipeline Triage Complete. Found {len(confirmed_findings)} True Positives.")

    if confirmed_findings:
        final_report_md = generate_final_report(confirmed_findings, repo_url)

        # Save to file
        report_path = "HYDROAD_UNIFIED_REPORT.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(final_report_md)

        print(f"\n[+] SUCCESS! Final Unified report generated and saved to: {report_path}")
    else:
        print("\n[+] No True Positives confirmed. No final report necessary.")


if __name__ == "__main__":
    # --- Interactive CLI Interface ---
    print("\n" + "=" * 65)
    print(" 🛡️ HYDROAD UNIFIED SCANNER - APPSEC & IAC EDITION 🛡️")
    print("=" * 65)

    target_github_url = ""

    # Allow passing the URL via command line, but fallback to interactive prompt
    if len(sys.argv) > 1:
        target_github_url = sys.argv[1]
    else:
        print("[*] Welcome to the automated AppSec & IaC pipeline.")
        target_github_url = input("[?] Please enter the exact GitHub Repository URL to scan: ").strip()

    if not target_github_url:
        print("\n[-] Error: No repository URL provided. Exiting operation.")
        sys.exit(1)

    print(f"\n[*] Target confirmed: {target_github_url}")
    print("[*] Initializing execution environment...")

    # 1. Environment Prep
    clean_up()
    clone_repository(target_github_url)

    # 2. Static Scanning
    run_semgrep_scan()

    # 3. AI Multi-Agent Orchestration
    run_multi_agent_pipeline(target_github_url)