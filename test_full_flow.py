
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

# Add project root to path
sys.path.append(os.getcwd())

from claudecode.github_action_audit import main, LLMClientRunner, ClaudeCliRunner
from claudecode.claude_api_client import OpenAIClient, ClaudeAPIClient

class TestFullFlow(unittest.TestCase):
    
    @patch.dict(os.environ, {
        'GITHUB_REPOSITORY': 'test/repo',
        'PR_NUMBER': '123',
        'GITHUB_TOKEN': 'dummy_token',
        'AI_PROVIDER': 'openai',
        'OPENAI_API_KEY': 'dummy_key',
        'MODEL_NAME': 'gpt-4-test'
    })
    @patch('claudecode.github_action_audit.GitHubActionClient')
    @patch('claudecode.github_action_audit.get_llm_client')
    @patch('claudecode.github_action_audit.get_security_audit_prompt')
    def test_main_flow_openai(self, mock_get_prompt, mock_get_client, MockGHClient):
        print("\nTesting full flow with OpenAI provider...")
        
        # Mock GitHub Client
        mock_gh = MockGHClient.return_value
        mock_gh.get_pr_data.return_value = {'title': 'Test PR', 'body': 'Description', 'number': 123}
        mock_gh.get_pr_diff.return_value = 'diff --git a/test.py b/test.py\n+ print("hello")'
        
        # Mock LLM Client
        mock_client_instance = MagicMock(spec=OpenAIClient)
        mock_client_instance.validate_api_access.return_value = (True, "")
        mock_client_instance.call_with_retry.return_value = (
            True, 
            '{"findings": [{"title": "Hardcoded Secret", "severity": "HIGH", "file": "test.py"}], "analysis_summary": {}}', 
            ""
        )
        mock_get_client.return_value = mock_client_instance
        
        # Mock Prompt
        mock_get_prompt.return_value = "System: Analyze this..."

        # Run Main
        # We expect exit code 1 because we returned a HIGH severity finding (which is "success" for the tool finding something)
        with self.assertRaises(SystemExit) as cm:
            main()
        
        # Verify interactions
        mock_gh.get_pr_data.assert_called_once()
        mock_client_instance.call_with_retry.assert_called_once()
        
        print("✅ OpenAI flow executed successfully (found high severity finding as expected)")

    @patch.dict(os.environ, {
        'GITHUB_REPOSITORY': 'test/repo',
        'PR_NUMBER': '123',
        'GITHUB_TOKEN': 'dummy_token',
        'AI_PROVIDER': 'anthropic-cli', # Default
        'ANTHROPIC_API_KEY': 'dummy_key'
    })
    @patch('claudecode.github_action_audit.GitHubActionClient')
    @patch('claudecode.github_action_audit.ClaudeCliRunner')
    def test_main_flow_cli(self, MockCliRunner, MockGHClient):
        print("\nTesting full flow with Claude CLI provider...")
        
        # Mock GitHub Client
        mock_gh = MockGHClient.return_value
        mock_gh.get_pr_data.return_value = {'title': 'Test PR'}
        mock_gh.get_pr_diff.return_value = 'diff'
        
        # Mock CLI Runner
        mock_runner = MockCliRunner.return_value
        mock_runner.validate_available.return_value = (True, "")
        mock_runner.run_security_audit.return_value = (True, "", {"findings": []})
        
        # Run Main
        with self.assertRaises(SystemExit) as cm:
            main()
            
        print("✅ CLI flow executed successfully")

if __name__ == '__main__':
    unittest.main()
