import os
from dotenv import load_dotenv
from litellm import completion

load_dotenv()

def test_key(model, key_env=None):
    if key_env:
        key = os.getenv(key_env)
        if not key:
            print(f"[-] No key found for {key_env}")
            return
    try:
        print(f"[*] Testing {model}...")
        response = completion(
            model=model,
            messages=[{"role": "user", "content": "Say hello"}],
            max_tokens=5
        )
        print(f"[+] Success! Response: {response.choices[0].message.content}")
    except Exception as e:
        print(f"[-] Failed: {str(e)}")

test_key("groq/llama-3.1-8b-instant", "GROQ_API_KEY")
test_key("groq/llama-3.3-70b-versatile", "GROQ_API_KEY")
test_key("gemini/gemini-3.1-flash-lite", "GEMINI_API_KEY")
test_key("ollama/llama3")
