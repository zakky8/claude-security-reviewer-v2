import requests
import json

BASE_URL = "http://localhost:8089"
API_KEY = "DYylzLTI.HXhARPLatmFmU3ccTTGrAM6I07lEtRXC"
MODEL = "moonshot-v1-8k" # Standard Moonshot model
API_BASE = "https://api.moonshot.cn/v1"

def verify_kimi():
    print(f"\n--- Verifying Kimi 2.5 Integration ({MODEL}) ---")
    payload = {
        "code_content": "def hello():\n    print('Hello Kimi')",
        "file_name": "hello_kimi.py",
        "provider": "openai", # Moonshot is OpenAI compatible
        "api_key": API_KEY,
        "model": MODEL,
        "api_base": API_BASE,
        "scan_type": "review"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        
        if response.status_code == 200:
            print("✅ SUCCESS: Kimi API accepted request.")
            data = response.json()
            if "findings" in data:
                 print(f"Findings Count: {len(data['findings'])}")
                 # Check if the fallback kicked in or if we got real findings
                 # If fallback kicked in, we'll see static findings only.
                 # If real findings, we might see more.
                 # Actually, we can check if 'analysis_summary' exists and has high/medium/low.
                 print(json.dumps(data.get('analysis_summary',{}), indent=2))
            else:
                 print("⚠️ No findings key in response.")
                 print(data)
        elif response.status_code == 500:
            print(f"❌ FAILURE: Server Error 500.")
            try:
                err_json = response.json()
                print(json.dumps(err_json, indent=2))
            except:
                print(response.text)
        else:
             print(f"❌ FAILURE: Status {response.status_code}")
             print(response.text)

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    verify_kimi()
