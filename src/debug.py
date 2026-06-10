import os
import requests

api_key = os.environ.get("GEMINI_API_KEY")

if not api_key:
    print("[-] GEMINI_API_KEY is not set!")
else:
    url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            print("[+] Available Gemini models for your API key:")
            models_data = response.json()
            for model in models_data.get("models", []):
                name = model.get("name")
                # נדפיס רק את המודלים של ג'מיני כדי לא להציף את המסך
                if "gemini" in name:
                    short_name = name.replace("models/", "")
                    print(f"  - gemini/{short_name}")
        else:
            print(f"[-] Failed to fetch models. Status code: {response.status_code}")
    except Exception as e:
        print(f"[-] Error: {e}")
