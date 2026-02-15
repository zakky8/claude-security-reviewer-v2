import requests
import json
import time

BASE_URL = "http://localhost:8095"

def run_final_debug():
    print("\n--- [FINAL DEBUG] ---")
    print("Testing simultaneous GitHub, Upload, and Paste sources...")
    
    # 1. Prepare multi-source payload
    # Note: We'll use a BAD GitHub URL to test resilience, 
    # and VALID paste/upload data to test detection.
    
    files = [
        ('files', ('vulnerable.js', 'eval(user_input); exec("rm -rf /");', 'application/javascript')),
        ('files', ('safe.txt', 'This is a safe file content.', 'text/plain'))
    ]
    
    data = {
        "github_url": "https://github.com/non-existent/bad-repo",
        "code_content": "import os\nos.system(cmd)", # PURE Python vulnerability
        "file_name": "snippet.py",
        "api_key": "fake_key_" + str(time.time()),
        "provider": "openai",
        "model": "gpt-4o",
        "scan_type": "security"
    }
    
    try:
        start_time = time.time()
        response = requests.post(f"{BASE_URL}/api/scan", data=data, files=files, timeout=30)
        duration = time.time() - start_time
        
        print(f"Request Duration: {duration:.2f}s")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            findings = result.get("findings", [])
            summary = result.get("analysis_summary", {})
            error_note = result.get("error", "")
            
            print("\n- [Resilience Check]")
            if "GitHub Clone Failed" in error_note:
                print("✅ Git failure detected and reported in 'error' field.")
            else:
                print("❌ Git failure NOT found in 'error' field.")
                
            if "LLM Analysis Failed" in error_note:
                print("✅ LLM failure detected (as expected with fake key).")
            else:
                print("❌ LLM failure NOT found in 'error' field.")

            print("\n- [Detection Check]")
            finding_titles = [f["title"].lower() for f in findings]
            
            # Static analysis should catch eval (JS), exec (JS), and os.system (Py)
            has_eval = any("eval" in t for t in finding_titles)
            has_exec = any("exec" in t for t in finding_titles)
            has_system = any("os.system" in t for t in finding_titles)
            
            if has_eval: print("✅ Static analysis caught 'eval()'")
            if has_exec: print("✅ Static analysis caught 'exec()'")
            if has_system: print("✅ Static analysis caught 'os.system()'")
            
            print(f"\n- [Summary Check]")
            print(f"Files Reviewed: {summary.get('files_reviewed')}")
            print(f"Total Findings: {len(findings)}")
            
            if len(findings) >= 3:
                print("\n🎉 [FINAL VERDICT: PASSED]")
            else:
                print("\n⚠️ [FINAL VERDICT: PARTIAL PASS - Missing findings]")
        else:
            print(f"\n❌ [FINAL VERDICT: FAILED] Server error: {response.text}")

    except Exception as e:
        print(f"\n❌ [FINAL VERDICT: EXCEPTION] {e}")

if __name__ == "__main__":
    run_final_debug()
