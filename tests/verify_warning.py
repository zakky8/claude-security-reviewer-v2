import requests
import json

BASE_URL = "http://localhost:8095"

def test_warning_fallback():
    print("\n--- Testing Warning Fallback (Invalid Key + Vulnerable Code) ---")
    
    # Payload with dangerous code but BAD key
    payload = {
        "code_content": "eval(user_input)", # Should trigger static analysis
        "file_name": "danger.py",
        "provider": "openai",
        "api_key": "bad_key_12345",
        "model": "gpt-4o",
        "scan_type": "security"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/api/scan", data=payload)
        
        print(f"Status: {response.status_code}")
        data = response.json()
        
        # We expect:
        # 1. Status 200 (Success despite LLM fail)
        # 2. 'error' field populated with LLM error details
        # 3. 'findings' list NOT empty (contains static finding)
        
        if response.status_code == 200:
            if "error" in data and "LLM Analysis Failed" in data["error"]:
                print("✅ PASSED: Server returned LLM failure message.")
                print(f"Error Message: {data['error']}")
            else:
                print("❌ FAILED: 'error' field missing or incorrect.")
                
            if len(data.get("findings", [])) > 0:
                print(f"✅ PASSED: Found {len(data['findings'])} static findings.")
                for f in data["findings"]:
                    print(f"   - {f['title']}")
            else:
                print("❌ FAILED: No static findings returned.")
        else:
            print(f"❌ FAILED: Unexpected status code {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    test_warning_fallback()
