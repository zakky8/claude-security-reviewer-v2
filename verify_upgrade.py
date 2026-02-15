import requests
import os
import sys
import time
import subprocess
import secrets

# Configuration
BASE_URL = "http://localhost:8089"
API_TOKEN = secrets.token_urlsafe(32)

class Verifier:
    def __init__(self):
        self.failures = 0

    def print_pass(self, msg):
        print(f"✅ PASS: {msg}")

    def print_fail(self, msg):
        print(f"❌ FAIL: {msg}")
        self.failures += 1

    def check_health(self):
        try:
            resp = requests.get(f"{BASE_URL}/health", timeout=5)
            if resp.status_code == 200 and resp.json().get("status") == "healthy":
                self.print_pass("Health check endpoint")
            else:
                self.print_fail(f"Health check failed. Status: {resp.status_code}, Body: {resp.text}")
        except Exception as e:
            self.print_fail(f"Health check exception: {e}")

    def check_auth_required(self):
        try:
            # No token
            resp = requests.post(f"{BASE_URL}/api/scan", data={"code_content": "print('hello')"})
            if resp.status_code == 401:
                self.print_pass("Authentication required (401 received without token)")
            else:
                self.print_fail(f"Authentication check failed. Expected 401, got {resp.status_code}")
        except Exception as e:
            self.print_fail(f"Auth check exception: {e}")

    def check_auth_success(self):
        try:
            # With token
            headers = {"Authorization": f"Bearer {API_TOKEN}"}
            resp = requests.post(f"{BASE_URL}/api/scan", headers=headers, data={"code_content": "print('hello')", "api_key": "dummy"})
            
            if resp.status_code != 401:
                self.print_pass(f"Authentication success (Allowed with token). Status: {resp.status_code}")
            else:
                self.print_fail("Authentication failed even with valid token (401 received)")
        except Exception as e:
            self.print_fail(f"Auth success check exception: {e}")

    def check_github_validation(self):
        try:
            headers = {"Authorization": f"Bearer {API_TOKEN}"}
            # Invalid URL
            resp = requests.post(f"{BASE_URL}/api/scan", headers=headers, data={
                "github_url": "ftp://github.com/evil/repo",
                "api_key": "dummy"
            })
            if "Invalid GitHub URL" in resp.text or resp.status_code == 400:
                 self.print_pass("GitHub URL validation (Rejected invalid URL)")
            else:
                 self.print_fail(f"GitHub URL validation failed. Expected rejection, got {resp.status_code}")
        except Exception as e:
            self.print_fail(f"GitHub validation exception: {e}")

    def run(self):
        print("--- Verifying Claude Security Reviewer v2.1.0 ---")
        
        # 1. Start Server (in background)
        print("Starting server...")
        # Use text=True for string output
        env = os.environ.copy()
        env["API_TOKEN"] = API_TOKEN
        env["PORT"] = "8089"
        
        proc = subprocess.Popen([sys.executable, "server.py"], 
                                cwd=os.getcwd(),
                                env=env,
                                stdout=subprocess.PIPE, 
                                stderr=subprocess.PIPE,
                                text=True)
        
        time.sleep(5) # Wait for startup
        
        try:
            if proc.poll() is not None:
                self.print_fail("Server failed to start")
                out, err = proc.communicate()
                print(f"Stdout: {out}")
                print(f"Stderr: {err}")
                return

            self.check_health()
            self.check_auth_required()
            self.check_auth_success()
            self.check_github_validation()
            
        finally:
            print("Stopping server...")
            proc.terminate()
            try:
                 proc.wait(timeout=5)
            except:
                 proc.kill()

        if self.failures == 0:
            print("\n✅ ALL CHECKS PASSED")
            sys.exit(0)
        else:
            print(f"\n❌ {self.failures} CHECKS FAILED")
            sys.exit(1)

if __name__ == "__main__":
    Verifier().run()
