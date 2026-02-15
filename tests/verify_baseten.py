import requests
import json
import os

BASE_URL = "http://localhost:8089"
API_KEY = "DYylzLTI.HXhARPLatmFmU3ccTTGrAM6I07lEtRXC"
MODEL = "moonshotai/Kimi-K2.5"
API_BASE = "https://inference.baseten.co/v1"

def verify_baseten():
    print(f"\n--- Verifying Baseten Integration ({MODEL}) ---")
    payload = {
        "code_content": "def hello():\n    print('Hello Kimi via Baseten')",
        "file_name": "hello_baseten.py",
        "provider": "openai", # Baseten is OpenAI compatible
        "api_key": API_KEY,
        "model": MODEL,
        "api_base": API_BASE,
        "scan_type": "review" 
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        
        if response.status_code == 200:
            print("✅ SUCCESS: Baseten API accepted request.")
            data = response.json()
            if "findings" in data:
                 print(f"Findings Count: {len(data['findings'])}")
                 print("Analysis Summary:")
                 print(json.dumps(data.get('analysis_summary',{}), indent=2))
                 
                 # Check if we got real analysis or fallback
                 if "LLM Analysis Failed" in data.get("error", ""):
                     print("⚠️ WARNING: Fallback triggered. Error:", data.get("error"))
                 else:
                     print("🎉 FULL SUCCESS: LLM analysis completed.")
            else:
                 print("⚠️ No findings key in response.")
                 print(data)
        elif response.status_code == 500:
            print(f"❌ FAILURE: Server Error 500.")
            try:
                print(json.dumps(response.json(), indent=2))
            except:
                print(response.text)
        else:
             print(f"❌ FAILURE: Status {response.status_code}")
             print(response.text)

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    verify_baseten()
