
import requests
import json

BASE_URL = "http://localhost:8089"

def test_static_analysis_hook():
    print("\n--- Testing Static Analysis Hook (eval) ---")
    payload = {
        "code_content": "function test() { eval('console.log(1)'); }",
        "file_name": "unsafe.js",
        "api_key": "dummy_key_to_fail_llm",
        "model": "gpt-4o",
        "scan_type": "security"
    }
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        data = response.json()
        
        # We expect a 200 OK because of our fallback logic, OR a response with 'findings'
        # Even if it returns 200, we check if static analysis caught the 'eval'
        
        if "findings" in data:
            eval_findings = [f for f in data["findings"] if "eval" in f["title"].lower() or "eval" in f["description"].lower()]
            if eval_findings:
                print(f"✅ SUCCESS: Static analysis caught 'eval()'. Finding: {eval_findings[0]['title']}")
            else:
                print("❌ FAILURE: Static analysis did NOT catch 'eval()'.")
                print(f"Findings: {json.dumps(data.get('findings'), indent=2)}")
        else:
             print(f"❌ FAILURE: No findings returned. Response: {data}")

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

def test_code_review_mode():
    print("\n--- Testing Code Review Mode (scan_type='review') ---")
    payload = {
        "code_content": "def foo():\n    return 1",
        "file_name": "clean.py",
        "api_key": "dummy_key_to_fail_llm", # validation will fail, but we check if server accepted the param
        "model": "gpt-4o",
        "scan_type": "review"
    }
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        # We just want to ensure the server didn't crash 500 without a useful error, 
        # or that it returned static findings (empty list is fine)
        # detailed verification of the *prompt* change is hard without a real LLM key,
        # but if we get the JSON response structure, the endpoint logic is working.
        if response.status_code == 200 or (response.status_code == 500 and "Audit Failed" in response.text):
             print(f"✅ SERVER ALIVE: Response code {response.status_code} received.")
             if response.status_code == 200 and "LLM Analysis Failed" in str(response.json()):
                 print("✅ FALLBACK WORKING: Server returned static analysis despite LLM failure.")
        else:
             print(f"❌ FAILURE: Unexpected response {response.status_code}")
             
    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    try:
        requests.get(BASE_URL)
        print(f"Server is running at {BASE_URL}")
        test_static_analysis_hook()
        test_code_review_mode()
    except Exception:
        print(f"❌ Server is NOT running at {BASE_URL}")
