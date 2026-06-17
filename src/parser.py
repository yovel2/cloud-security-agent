import json
import os


class SemgrepParser:
    """
    Handles the ingestion and structural decomposition of raw Semgrep SAST/IaC JSON artifacts.
    """

    def __init__(self, json_path="/tmp/semgrep_results.json"):
        self.json_path = json_path

    def _get_code_context(self, file_path, line_num, context_size=3):
        """
        Bypasses Semgrep's flawed text extraction by reading the target file directly.
        Extracts the vulnerable line along with surrounding context lines.
        """
        if not file_path or not line_num:
            return "Context unavailable (missing path or line number)."

        if not os.path.exists(file_path):
            return f"Context unavailable (file not found on disk: {file_path})."

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            # Convert 1-based line number to 0-based list index
            target_idx = line_num - 1
            start_idx = max(0, target_idx - context_size)
            end_idx = min(len(lines), target_idx + context_size + 1)

            context_block = []
            for i in range(start_idx, end_idx):
                # Add an arrow '>>' to highlight the exact line Semgrep flagged
                prefix = ">> " if i == target_idx else "   "
                context_block.append(f"{prefix}{i + 1}: {lines[i].rstrip()}")

            return "\n".join(context_block)

        except Exception as e:
            return f"Context extraction failed: {str(e)}"

    def parse_findings(self):
        """
        Parses the targeted Semgrep JSON log file and extracts localized contexts.
        """
        if not os.path.exists(self.json_path):
            print(f"[-] Parsing Failure: Target artifact not found at {self.json_path}")
            return []

        try:
            with open(self.json_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] Formatting Error: Failed to parse structural JSON semantics: {e}")
            return []

        extracted_findings = []

        for result in raw_data.get("results", []):
            target_file = result.get("path")
            line_start = result.get("start", {}).get("line")

            # --- THE FIX: Fetch real code from disk instead of trusting Semgrep ---
            actual_code_block = self._get_code_context(target_file, line_start)

            # Extract AppSec-specific metadata fields from Semgrep's metadata block
            semgrep_metadata = result.get("extra", {}).get("metadata", {})

            finding_metadata = {
                "rule_id": result.get("check_id"),
                "target_file": target_file,
                "line_start": line_start,
                "line_end": result.get("end", {}).get("line"),
                "analyzer_message": result.get("extra", {}).get("message"),
                "severity_level": result.get("extra", {}).get("severity"),
                "cwe": semgrep_metadata.get("cwe", []),
                "owasp": semgrep_metadata.get("owasp", []),
                "vulnerability_class": semgrep_metadata.get("vulnerability_class", []),
                "category": semgrep_metadata.get("category", "UNKNOWN"),
                "technology": semgrep_metadata.get("technology", []),
                "impact": semgrep_metadata.get("impact", "UNKNOWN"),
                "confidence": semgrep_metadata.get("confidence", "UNKNOWN"),
                "dataflow_trace": result.get("extra", {}).get("dataflow_trace"),
                "metavars": result.get("extra", {}).get("metavars"),
                "semgrep_fix": result.get("extra", {}).get("fix"),
                "affected_code": actual_code_block  # Assigned the real code block here!
            }
            extracted_findings.append(finding_metadata)

        return extracted_findings
    
if __name__ == "__main__":
    # Local unit test context to verify extraction parameters
    # Assumes a volume configuration or direct pipeline execution inside the container
    SAMPLE_PATH = "/tmp/semgrep_results.json"

    print(f"[*] Initializing parser diagnostic sequence against: {SAMPLE_PATH}")
    test_parser = SemgrepParser(SAMPLE_PATH)
    discovered_flaws = test_parser.parse_findings()
    print(f"[+] Diagnostic sequence completed. Extracted {len(discovered_flaws)} semantic objects.")