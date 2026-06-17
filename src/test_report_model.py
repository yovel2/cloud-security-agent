import os
from litellm import completion

def test_model(model_name):
    print(f"[*] Testing model: {model_name} ...")
    try:
        response = completion(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a professional Cyber Security Analyst."},
                {"role": "user", "content": "Write a 1-sentence summary of what a SQL Injection is."}
            ],
            timeout=15  # טיימאאוט קצר כדי שלא נחכה סתם אם השרת לא מגיב
        )
        print("[+] Success! Response:")
        print(f"    {response.choices[0].message.content.strip()}\n")
        return True
    except Exception as e:
        print(f"[-] Failed! Error:")
        print(f"    {e}\n")
        return False

if __name__ == "__main__":
    print("="*50)
    print("   🔍 REPORTING MODEL SANITY CHECK")
    print("="*50)

    # רשימת המודלים שנרצה לבחון לדוח הסופי
    models_to_test = [
        "cohere/command-r-plus-08-2024",  # הגרסה הספציפית והמעודכנת של Cohere
        "cohere/command-r-08-2024",       # הגרסה הקלה יותר של Cohere
        "groq/llama-3.3-70b-versatile"    # ה-Llama שראינו שעובד לך נהדר כסוכן גיבוי לדוח
    ]

    for model in models_to_test:
        test_model(model)