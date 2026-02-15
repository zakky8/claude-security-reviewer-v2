import requests
import json

BASE_URL = "http://localhost:8095"

def test_multi_source_resilience():
    print("\n--- Testing Multi-Source Resilience (Failed GitHub + Valid Paste) ---")
    
    # Payload with a BAD GitHub URL but VALID pasted code
    payload = {
        "github_url": "https://github.com/non-existent-repo-12345",
        "code_content": "eval(dangerous_input)", # Should be caught by static analysis
        "api_key": "bad_key",
        "provider": "openai",
        "model": "gpt-4o"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        
        print(f"Status Code: {response.status_code}")
        data = response.json()
        
        # We expect:
        # 1. 200 OK (because pasted code was found)
        # 2. 'findings' contains eval check
        # 3. 'error' contains BOTH Git failure and LLM failure
        
        if response.status_code == 200:
            print("✅ SUCCESS: Server processed pasted code despite Git failure.")
            
            if "error" in data:
                print(f"Server Message: {data['error']}")
                if "GitHub Clone Failed" in data['error']:
                    print("✅ CONFIRMED: Git failure mentioned in response.")
                if "LLM Analysis Failed" in data['error']:
                    print("✅ CONFIRMED: LLM failure mentioned in response.")
            
            findings = data.get("findings", [])
            if any("eval" in f["title"].lower() for f in findings):
                print("✅ CONFIRMED: Static analysis caught 'eval' in pasted code.")
            else:
                print("❌ FAILED: 'eval' not found in findings.")
        else:
            print(f"❌ FAILED: Server returned status {response.status_code}")
            print(json.dumps(data, indent=2))

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    test_multi_source_resilience()
