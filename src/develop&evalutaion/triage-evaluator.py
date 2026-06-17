import json
import csv
import time
from triage_agent import LLMTriageAgent



def run_evaluation():
    print("[*] Starting LLM Benchmarking Process (CSV-Only Mode)...")

    with open('src/models.json', 'r') as f:
        models_to_test = json.load(f)["models"]

    ground_truth = load_ground_truth()
    if not ground_truth:
        return

    # Transform ground truth dictionary into mock finding objects for the LLM agent
    test_subset = []
    for key, data in ground_truth.items():
        rule_id, file_and_line = key.split('|', 1)
        
        if ':' in file_and_line:
            file_path, line_num = file_and_line.split(':', 1)
        else:
            file_path, line_num = file_and_line, "0"

        mock_finding = {
            "rule_id": rule_id,
            "target_file": file_path,
            "line_start": line_num,
            "affected_code": data.get("affected_code", "No code provided"),
            "expected_classification": data["classification"],
            "expected_patch": data["expected_patch"]
        }
        test_subset.append(mock_finding)

    print(f"[*] Loaded {len(test_subset)} simulated findings directly from CSV.")

    report_path = "hydroad_patch_report.txt"
    metrics_csv_path = "hydroad_triage_metrics.csv"

    with open(report_path, "w", encoding="utf-8") as report_file, \
         open(metrics_csv_path, "w", encoding="utf-8", newline='') as metrics_file:
        
        # Initialize the CSV writer for graph metrics
        csv_writer = csv.writer(metrics_file)
        csv_writer.writerow(["Model", "Total Tested", "Accuracy (%)", "True Positives Found", "False Positives Filtered", "Missed Vulns (FN)", "False Alarms (FP)"])

        report_file.write("=" * 80 + "\n")
        report_file.write("               HYDROAD - TWO-PHASE LLM ANALYSIS REPORT\n")
        report_file.write("=" * 80 + "\n\n")

        for model_name in models_to_test:
            print("\n" + "=" * 60)
            print(f"[*] Evaluating Model: {model_name}")
            print("=" * 60)

            report_file.write(f"### MODEL: {model_name} ###\n\n")

            agent = LLMTriageAgent(model_name=model_name)
            
            # Dictionary to track confusion matrix metrics for visualization
            stats = {
                "TP_match": 0, 
                "FP_match": 0, 
                "TP_miss": 0,  
                "FP_miss": 0,  
            }
            
            request_counter = 0

            # ---------------------------------------------------------
            # PHASE 1: TRIAGE (Classification & FP Filtering)
            # ---------------------------------------------------------
            print(f"[*] PHASE 1: Running Triage (Classification)...")
            report_file.write("--- PHASE 1: TRIAGE RESULTS ---\n")
            
            for finding in test_subset:
                request_counter += 1

                # Rate Limit Protection: Pause for 15 seconds every 5 requests to prevent 429 Resource Exhausted errors
                # We skip this for Llama-70B as Groq provisions higher throughput for flagship models.
                if "70b" not in model_name and request_counter % 5 == 0:
                    print(f"[*] Rate Limit protection active. Waiting 15 seconds (Request #{request_counter})...")
                    time.sleep(15)

                expected = finding['expected_classification']
                
                # Execute triage analysis
                result = agent.analyze_finding(finding)
                actual = result.get('classification', 'ERROR').upper()
                
                # Persist the classification result to the finding object for Phase 2
                finding['actual_classification'] = actual
                finding['triage_reasoning'] = result.get('justification', 'No reasoning provided.')

                # Calculate confusion matrix metrics
                if actual == expected:
                    if expected == 'TP':
                        stats["TP_match"] += 1
                    else:
                        stats["FP_match"] += 1
                    print(f"  [+] Triage Match: {finding['rule_id']} (Expected: {expected}, Got: {actual})")
                else:
                    if expected == 'TP':
                        stats["TP_miss"] += 1
                    else:
                        stats["FP_miss"] += 1
                    print(f"  [-] Mismatch: {finding['rule_id']} (Expected: {expected}, Got: {actual})")

                # Log Phase 1 results to the textual report
                report_file.write(f"Vuln: {finding['rule_id']} | Expected: {expected} | Actual: {actual}\n")
                report_file.write(f"Reasoning: {finding['triage_reasoning']}\n\n")

            # Finalize Phase 1 metrics and export to CSV
            total_predictions = len(test_subset)
            correct_predictions = stats["TP_match"] + stats["FP_match"]
            accuracy = (correct_predictions / total_predictions) * 100 if total_predictions > 0 else 0
            
            csv_writer.writerow([
                model_name, total_predictions, f"{accuracy:.2f}", 
                stats["TP_match"], stats["FP_match"], stats["TP_miss"], stats["FP_miss"]
            ])


    print(f"\n[+] Evaluation complete! Triage metrics saved to: {metrics_csv_path}")


if __name__ == "__main__":
    run_evaluation()