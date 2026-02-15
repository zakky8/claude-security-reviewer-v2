import requests
import json

BASE_URL = "http://localhost:8095"

def test_valid_github_scan():
    print("\n--- Testing Valid GitHub Scan ---")
    
    # Use a small, public repository for testing
    payload = {
        "github_url": "https://github.com/encode/starlette", # Guaranteed public repo
        "api_key": "any_key",
        "provider": "openai",
        "model": "gpt-4o"
    }
    
    try:
        # Increase timeout for clone + scan
        response = requests.post(f"{BASE_URL}/api/scan", data=payload, timeout=120)
        
        print(f"Status Code: {response.status_code}")
        data = response.json()
        
        if response.status_code == 200:
            print("✅ SUCCESS: Server successfully cloned and scanned the repository.")
            findings = data.get("findings", [])
            print(f"Found {len(findings)} findings.")
            files_reviewed = data.get("analysis_summary", {}).get("files_reviewed", 0)
            print(f"Files reviewed: {files_reviewed}")
        else:
            print(f"❌ FAILED: Server returned status {response.status_code}")
            print(json.dumps(data, indent=2))

    except Exception as e:
        print(f"❌ EXCEPTION: {e}")

if __name__ == "__main__":
    test_valid_github_scan()
