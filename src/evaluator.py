import json
import csv
import os
from triage_agent import LLMTriageAgent
from parser import SemgrepParser


def load_ground_truth(csv_path="src/ground_truth.csv"):
    """
    Reads the Ground Truth CSV and builds a dictionary for fast lookup.
    Robustly handles various file encodings typical of Windows/Excel exports.
    """
    truth_dict = {}
    if not os.path.exists(csv_path):
        print(f"[-] Missing Ground Truth file at {csv_path}")
        return truth_dict

    # Prioritize standard UTF-8 with BOM, fallback to Windows-specific encodings
    encodings_to_try = ['utf-8-sig', 'utf-8', 'cp1255', 'windows-1252', 'latin-1']

    for enc in encodings_to_try:
        try:
            with open(csv_path, mode='r', encoding=enc) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    rule_id = row['Rule ID'].strip()
                    file_and_line = row['Target File & Line'].strip()
                    target_class = row['Target Class'].strip().upper()

                    # Create a unique key: "rule_id|path/to/file:line"
                    key = f"{rule_id}|{file_and_line}"
                    truth_dict[key] = target_class

            # If the loop completes without UnicodeDecodeError, the encoding is correct
            return truth_dict

        except UnicodeDecodeError:
            # Current encoding failed, proceed to the next one in the list
            continue
        except KeyError as e:
            print(f"[-] CSV Header mismatch using encoding '{enc}'. Could not find column: {e}")
            return {}

    print("[-] Failed to read CSV with all attempted encodings.")
    return truth_dict

def run_evaluation():
    print("[*] Starting LLM Benchmarking Process...")

    # 1. Load configuration and ground truth
    with open('src/models.json', 'r') as f:
        models_to_test = json.load(f)["models"]

    ground_truth = load_ground_truth()
    if not ground_truth:
        return

    # 2. Parse Semgrep findings from the disk
    parser = SemgrepParser("/tmp/semgrep_results.json")
    all_findings = parser.parse_findings()

    # 3. Filter only the findings that exist in our Ground Truth test subset
    test_subset = []
    for finding in all_findings:
        target_key = f"{finding['rule_id']}|{finding['target_file']}:{finding['line_start']}"
        if target_key in ground_truth:
            # Attach the expected answer to the finding dictionary for later comparison
            finding['expected_classification'] = ground_truth[target_key]
            test_subset.append(finding)

    print(f"[*] Matched {len(test_subset)} findings against the Ground Truth database.")

    # 4. Evaluate each model dynamically
    for model_name in models_to_test:
        print("\n" + "=" * 50)
        print(f"[*] Evaluating Model: {model_name}")
        print("=" * 50)

        agent = LLMTriageAgent(model_name=model_name)
        correct_predictions = 0
        total_predictions = len(test_subset)

        for finding in test_subset:
            expected = finding['expected_classification']

            # Send the finding to the LLM
            result = agent.analyze_finding(finding)
            actual = result.get('classification', 'ERROR').upper()

            # Compare and score
            if actual == expected:
                correct_predictions += 1
                print(f"  [+] Match: {finding['rule_id']} (Expected: {expected}, Got: {actual})")
            else:
                print(f"  [-] Mismatch: {finding['rule_id']} (Expected: {expected}, Got: {actual})")
                print(f"      Reasoning provided: {result.get('justification')}")

        # 5. Calculate and display percentage
        if total_predictions > 0:
            accuracy = (correct_predictions / total_predictions) * 100
            print("-" * 50)
            print(f"[FINAL SCORE] {model_name} Accuracy: {accuracy:.2f}% ({correct_predictions}/{total_predictions})")
        else:
            print("[-] No testable predictions were made.")


if __name__ == "__main__":
    run_evaluation()