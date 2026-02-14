
import os
import sys
import logging
from unittest.mock import MagicMock, patch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

def verify_system():
    print("\n🔍 STARTING SYSTEM VERIFICATION...\n")
    
    # 1. 📦 Check Dependencies
    print("1️⃣  Checking Dependencies...")
    try:
        import claudecode
        import openai
        import anthropic
        import tenacity
        print("   ✅ All required packages are installed.")
    except ImportError as e:
        print(f"   ❌ Missing dependency: {e}")
        return False

    # 2. 🏭 Verify Client Factory
    print("\n2️⃣  Verifying AI Provider Logic...")
    from claudecode import claude_api_client
    try:
        # Test OpenAI creation
        client = claude_api_client.get_llm_client(
            provider='openai',
            api_key='sk-dummy-key',
            model='gpt-4o'
        )
        if isinstance(client, claude_api_client.OpenAIClient):
            print("   ✅ OpenAI Client factory works.")
        else:
            print(f"   ❌ OpenAI Client factory failed.")
            return False
            
        # Test Custom/Localhost creation
        client = claude_api_client.get_llm_client(
            provider='custom',
            api_key='dummy',
            api_base='http://localhost:8080/v1'
        )
        if hasattr(client, 'api_base') and client.api_base == 'http://localhost:8080/v1':
             print("   ✅ Custom/Localhost Configuration works.")
    except Exception as e:
        print(f"   ❌ Client factory exception: {e}")
        return False

    # 3. 🛡️ Simulate Full Audit (Mocked)
    print("\n3️⃣  Running Simulated Security Audit...")
    print("   (This mocks the API so no real keys are needed)")
    
    try:
        # We enforce these env vars for the simulation
        env_updates = {
            'GITHUB_REPOSITORY': 'test/verification-repo', 
            'PR_NUMBER': '101', 
            'GITHUB_TOKEN': 'dummy-token',
            'AI_PROVIDER': 'openai',
            'OPENAI_API_KEY': 'sk-dummy-key'
        }
        
        with patch.dict(os.environ, env_updates):
            # Mock GitHub Client to stay offline
            with patch('claudecode.github_action_audit.GitHubActionClient') as MockGH:
                mock_gh_instance = MockGH.return_value
                mock_gh_instance.get_pr_data.return_value = {'title': 'Verify PR', 'number': 101, 'body': 'test'}
                mock_gh_instance.get_pr_diff.return_value = 'diff --git a/main.py b/main.py\n+ secret = "12345"'
                
                # Mock LLM Client to return a fake finding
                with patch.object(claude_api_client.OpenAIClient, 'call_with_retry') as mock_call:
                    mock_call.return_value = (True, '{"findings": [{"title": "Test Finding", "severity": "HIGH", "file": "main.py"}]}', "")
                    
                    from claudecode.github_action_audit import initialize_clients, run_security_audit
                    
                    gh_client, runner = initialize_clients()
                    print(f"   ✅ Initialized runner type: {type(runner).__name__}")
                    
                    # Run audit
                    result = run_security_audit(runner, "Analyze this...")
                    
                    findings = result.get('findings', [])
                    if len(findings) == 1 and findings[0]['title'] == 'Test Finding':
                        print(f"   ✅ Audit simulation successful! Found {len(findings)} security finding(s).")
                    else:
                        print("   ❌ Audit simulation failed to return expected findings.")
                        return False
                    
    except Exception as e:
        print(f"   ❌ Simulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("\n🎉 VERIFICATION COMPLETE: ALL SYSTEMS GO!")
    print("   You can now use this action in your GitHub Workflows or locally.")
    return True

if __name__ == "__main__":
    success = verify_system()
    sys.exit(0 if success else 1)
