import json
import csv
import os
from triage_agent import LLMTriageAgent
from parser import SemgrepParser


def load_ground_truth(csv_path="src/ground_truth.csv"):
    truth_dict = {}
    if not os.path.exists(csv_path):
        print(f"[-] Missing Ground Truth file at {csv_path}")
        return truth_dict

    try:
        with open(csv_path, 'r', encoding='utf-8-sig') as f:
            first_line = f.readline()
            delimiter = ';' if ';' in first_line else ','
    except Exception:
        delimiter = ','

    encodings_to_try = ['utf-8-sig', 'utf-8', 'cp1255', 'windows-1252', 'latin-1']

    for enc in encodings_to_try:
        try:
            with open(csv_path, mode='r', encoding=enc) as f:
                reader = csv.DictReader(f, delimiter=delimiter)

                clean_headers = {}
                if reader.fieldnames:
                    for field in reader.fieldnames:
                        clean_headers[field.strip()] = field

                if 'Rule ID' not in clean_headers or 'Target Class' not in clean_headers:
                    raise KeyError(f"Missing columns in encoding {enc}")

                for row in reader:
                    rule_id = row[clean_headers['Rule ID']].strip()
                    file_and_line = row[clean_headers['Target File & Line']].strip()
                    target_class = row[clean_headers['Target Class']].strip().upper()

                    # Extract the expected patch if the column exists
                    expected_patch = ""
                    if 'Expected Patch' in clean_headers:
                        expected_patch = row[clean_headers['Expected Patch']].strip()

                    key = f"{rule_id}|{file_and_line}"
                    # Now storing a dictionary of expected values
                    truth_dict[key] = {
                        "classification": target_class,
                        "expected_patch": expected_patch
                    }
            return truth_dict

        except UnicodeDecodeError:
            continue
        except KeyError:
            continue

    print("[-] Failed to read CSV with all attempted encodings.")
    return truth_dict


def run_evaluation():
    print("[*] Starting LLM Benchmarking Process...")

    with open('src/models.json', 'r') as f:
        models_to_test = json.load(f)["models"]

    ground_truth = load_ground_truth()
    if not ground_truth:
        return

    parser = SemgrepParser("/tmp/semgrep_results.json")
    all_findings = parser.parse_findings()

    test_subset = []
    for finding in all_findings:
        clean_path = finding['target_file'].replace('/tmp/target_repo/', '').lstrip('/')
        short_rule = finding['rule_id'].split('.')[-1]
        target_key = f"{short_rule}|{clean_path}:{finding['line_start']}"

        if target_key in ground_truth:
            finding['expected_classification'] = ground_truth[target_key]["classification"]
            finding['expected_patch'] = ground_truth[target_key]["expected_patch"]
            test_subset.append(finding)

    print(f"[*] Matched {len(test_subset)} findings against the Ground Truth database.")

    # --- פתיחת קובץ הדוח המחקרי לכתיבה ---
    report_path = "hydroad_patch_report.txt"
    with open(report_path, "w", encoding="utf-8") as report_file:
        report_file.write("=" * 80 + "\n")
        report_file.write("               HYDROAD - LLM REMEDIATION PATCH ANALYSIS REPORT\n")
        report_file.write("=" * 80 + "\n\n")

        for model_name in models_to_test:
            print("\n" + "=" * 60)
            print(f"[*] Evaluating Model: {model_name}")
            print("=" * 60)

            report_file.write(f"### MODEL: {model_name} ###\n\n")

            agent = LLMTriageAgent(model_name=model_name)
            correct_predictions = 0
            total_predictions = len(test_subset)

            for finding in test_subset:
                expected = finding['expected_classification']
                expected_patch = finding['expected_patch']

                result = agent.analyze_finding(finding)
                actual = result.get('classification', 'ERROR').upper()

                if actual == expected:
                    correct_predictions += 1
                    print(f"  [+] Triage Match: {finding['rule_id']} (Expected: {expected}, Got: {actual})")

                    if actual == 'TP':
                        print(f"      [*] Generating remediation patch...")
                        patch_response = agent.generate_patch(finding)
                        model_fix = patch_response.get("fixed_code", "No code provided.")
                        model_strategy = patch_response.get("patch_strategy", "No strategy provided.")

                        # --- כתיבה מעוצבת לתוך הקובץ ---
                        report_file.write(f"Vulnerability: {finding['rule_id']}\n")
                        report_file.write(f"Location:      {finding['target_file']}:{finding['line_start']}\n")
                        report_file.write("-" * 80 + "\n")
                        report_file.write("[EXPECTED STRATEGY - GROUND TRUTH]\n")
                        report_file.write(f"{expected_patch}\n\n")
                        report_file.write("[MODEL'S PROPOSED STRATEGY]\n")
                        report_file.write(f"{model_strategy}\n\n")
                        report_file.write("[MODEL'S GENERATED CODE FIX]\n")
                        report_file.write(f"{model_fix}\n")
                        report_file.write("=" * 80 + "\n\n")

                else:
                    print(f"  [-] Mismatch: {finding['rule_id']} (Expected: {expected}, Got: {actual})")
                    print(f"      Reasoning provided: {result.get('justification')}")

            if total_predictions > 0:
                accuracy = (correct_predictions / total_predictions) * 100
                print("-" * 60)
                print(
                    f"[FINAL SCORE] {model_name} Triage Accuracy: {accuracy:.2f}% ({correct_predictions}/{total_predictions})")

                # שמירת הציון הסופי של המודל בתחתית הפרק שלו בדוח
                report_file.write(f"--> Final Triage Accuracy for {model_name}: {accuracy:.2f}%\n")
                report_file.write("*" * 80 + "\n\n")
            else:
                print("[-] No testable predictions were made.")

    print(f"\n[+] Benchmarking complete! Patch analysis report successfully saved to: {report_path}")


if __name__ == "__main__":
    run_evaluation()

if __name__ == "__main__":
    run_evaluation()