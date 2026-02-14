
import os
import sys
import logging
from unittest.mock import MagicMock, patch

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def verify_system():
    print("--- Verifying Claude Code Security Review Installation ---")
    
    # 1. Check Imports
    try:
        import claudecode
        from claudecode import claude_api_client
        from claudecode import github_action_audit
        print("✅ Core modules imported successfully.")
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

    # 2. Verify Provider Logic (OpenAI)
    try:
        client = claude_api_client.get_llm_client(
            provider='openai',
            api_key='sk-dummy-key',
            model='gpt-3.5-turbo'
        )
        if isinstance(client, claude_api_client.OpenAIClient):
            print("✅ OpenAI Client factory working.")
        else:
            print(f"❌ OpenAI Client factory failed: Got {type(client)}")
            return False
    except Exception as e:
        print(f"❌ Client factory exception: {e}")
        return False

    # 3. Simulate Run (Mocked)
    print("Running simulated audit (mocked)...")
    try:
        with patch('claudecode.github_action_audit.GitHubActionClient') as MockGH:
            with patch.dict(os.environ, {
                'GITHUB_REPOSITORY': 'test/repo', 
                'PR_NUMBER': '1', 
                'GITHUB_TOKEN': 'dummy'
            }):
                # Mock the API call so we don't need a real key/network
                with patch.object(claude_api_client.OpenAIClient, 'call_with_retry', return_value=(True, '{"findings": []}', "")):
                    from claudecode.github_action_audit import initialize_clients, run_security_audit
                    
                    # Set provider to OpenAI
                    os.environ['AI_PROVIDER'] = 'openai'
                    os.environ['OPENAI_API_KEY'] = 'dummy'
                    
                    gh_client, runner = initialize_clients()
                    print(f"✅ Initialized runner: {type(runner).__name__}")
                    
                    # Run audit
                    result = run_security_audit(runner, "System: Analyze this code...")
                    print(f"✅ Audit execution successful. Findings: {len(result.get('findings', []))}")
                    
    except Exception as e:
        print(f"❌ Simulation failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    print("\n🎉 VERIFICATION COMPLETE: The system is ready to use!")
    return True

if __name__ == "__main__":
    success = verify_system()
    sys.exit(0 if success else 1)
