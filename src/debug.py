import json
import os


def check_raw_json():
    json_path = "/tmp/semgrep_results.json"

    if not os.path.exists(json_path):
        print(f"[-] Cannot find {json_path}. Did you run main.py first?")
        return

    with open(json_path, 'r', encoding='utf-8') as f:
        raw_data = json.load(f)

    results = raw_data.get("results", [])

    if not results:
        print("[-] JSON is empty (no results).")
        return

    print("\n" + "=" * 60)
    print("[*] RAW SEMGREP JSON FOR THE FIRST FINDING:")
    print("=" * 60)

    print(json.dumps(results[0], indent=4))
    print("=" * 60)


if __name__ == "__main__":
    check_raw_json()