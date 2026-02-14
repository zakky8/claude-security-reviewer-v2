"""Generic LLM client for AI-powered security analysis."""

import os
import json
import time
import logging
from typing import Dict, Any, Tuple, Optional, List, Union
from pathlib import Path
from abc import ABC, abstractmethod

# Attempt to import dependencies, handling missing ones gracefully
try:
    from anthropic import Anthropic, RateLimitError as AnthropicRateLimitError, APIStatusError as AnthropicAPIStatusError, APITimeoutError as AnthropicAPITimeoutError
except ImportError:
    Anthropic = None
    
try:
    from openai import OpenAI, RateLimitError as OpenAIRateLimitError, APIStatusError as OpenAIAPIStatusError, APITimeoutError as OpenAIAPITimeoutError
except ImportError:
    OpenAI = None

from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from claudecode.constants import (
    DEFAULT_CLAUDE_MODEL, DEFAULT_TIMEOUT_SECONDS, DEFAULT_MAX_RETRIES,
    PROMPT_TOKEN_LIMIT,
)

DEFAULT_OPENAI_MODEL = "gpt-4"

from claudecode.json_parser import parse_json_with_fallbacks
from claudecode.logger import get_logger

logger = get_logger(__name__)

class CircuitBreakerError(Exception):
    """Raised when circuit breaker trips due to consecutive failures."""
    pass

class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    def __init__(self, 
                 model: Optional[str] = None,
                 api_key: Optional[str] = None,
                 api_base: Optional[str] = None,
                 timeout_seconds: Optional[int] = None,
                 max_retries: Optional[int] = None,
                 circuit_breaker_threshold: int = 3):
        self.model = model
        self.api_key = api_key
        self.api_base = api_base
        self.timeout_seconds = timeout_seconds or DEFAULT_TIMEOUT_SECONDS
        self.max_retries = max_retries or DEFAULT_MAX_RETRIES
        self.circuit_breaker_threshold = circuit_breaker_threshold
        
        self.consecutive_failures = 0
        self.circuit_open = False
        
    def _check_circuit_breaker(self) -> None:
        if self.circuit_open:
            raise CircuitBreakerError(
                f"Circuit breaker open after {self.consecutive_failures} consecutive failures. "
                "Please check API connectivity and rate limits before retrying."
            )
            
    def _record_success(self) -> None:
        self.consecutive_failures = 0
        if self.circuit_open:
            logger.info("Circuit breaker closed after successful call")
            self.circuit_open = False
            
    def _record_failure(self) -> None:
        self.consecutive_failures += 1
        logger.warning(f"Consecutive API failures: {self.consecutive_failures}/{self.circuit_breaker_threshold}")
        if self.consecutive_failures >= self.circuit_breaker_threshold:
            self.circuit_open = True
            logger.error(f"Circuit breaker opened after {self.consecutive_failures} consecutive failures")

    @abstractmethod
    def validate_api_access(self) -> Tuple[bool, str]:
        """Validate API access."""
        pass

    @abstractmethod
    def call_with_retry(self, 
                       prompt: str,
                       system_prompt: Optional[str] = None,
                       max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        """Make API call with retry logic."""
        pass

    def analyze_single_finding(self, 
                               finding: Dict[str, Any], 
                               pr_context: Optional[Dict[str, Any]] = None,
                               custom_filtering_instructions: Optional[str] = None) -> Tuple[bool, Dict[str, Any], str]:
        """Analyze a single security finding (common logic)."""
        try:
            prompt = self._generate_single_finding_prompt(finding, pr_context, custom_filtering_instructions)
            system_prompt = self._generate_system_prompt()
            
            success, response_text, error_msg = self.call_with_retry(
                prompt=prompt,
                system_prompt=system_prompt,
                max_tokens=PROMPT_TOKEN_LIMIT 
            )
            
            if not success:
                return False, {}, error_msg
            
            success, analysis_result = parse_json_with_fallbacks(response_text, "LLM API response")
            if success:
                logger.info(f"Successfully parsed {self.__class__.__name__} response for single finding")
                return True, analysis_result, ""
            else:
                return False, {}, "Failed to parse JSON response"
                
        except Exception as e:
            logger.exception(f"Error during single finding security analysis: {str(e)}")
            return False, {}, f"Single finding security analysis failed: {str(e)}"

    def _generate_system_prompt(self) -> str:
        return """You are a security expert reviewing findings from an automated code audit tool.
Your task is to filter out false positives and low-signal findings to reduce alert fatigue.
You must maintain high recall (don't miss real vulnerabilities) while improving precision.

Respond ONLY with valid JSON in the exact format specified in the user prompt.
Do not include explanatory text, markdown formatting, or code blocks."""

    def _generate_single_finding_prompt(self, finding: Dict[str, Any], pr_context: Optional[Dict[str, Any]] = None, custom_filtering_instructions: Optional[str] = None) -> str:
        pr_info = ""
        if pr_context and isinstance(pr_context, dict):
            pr_info = f"""
PR Context:
- Repository: {pr_context.get('repo_name', 'unknown')}
- PR #{pr_context.get('pr_number', 'unknown')}
- Title: {pr_context.get('title', 'unknown')}
- Description: {(pr_context.get('description') or 'No description')[:500]}...
"""
        
        file_path = finding.get('file', '')
        file_content = ""
        if file_path:
            success, content, error = self._read_file(file_path)
            if success:
                file_content = f"\nFile Content ({file_path}):\n```\n{content}\n```"
            else:
                file_content = f"\nFile Content ({file_path}): Error reading file - {error}\n"
        
        finding_json = json.dumps(finding, indent=2)
        
        if custom_filtering_instructions:
            filtering_section = custom_filtering_instructions
        else:
             filtering_section = """HARD EXCLUSIONS - Automatically exclude findings matching these patterns:
1. Denial of Service (DOS) vulnerabilities
2. Secrets/credentials stored on disk
3. Rate limiting concerns
4. Memory/CPU exhaustion
5. Missing input validation on non-critical fields
6. Github action workflow sanitization concerns
7. General lack of hardening
8. Theoretical race conditions
9. Outdated third-party libraries
10. Memory safety in Rust
11. Test files
12. Log spoofing (unless sensitive)
13. SSRF controlling only path
14. AI prompt injection
15. Unavailable internal dependencies
16. Crashes/Null pointers

SIGNAL QUALITY CRITERIA:
1. Concrete exploitable vulnerability?
2. Real risk vs theoretical?
3. Specific code locations?
4. Actionable?
"""
        
        return f"""I need you to analyze a security finding from an automated code audit and determine if it's a false positive.

{pr_info}

{filtering_section}

Assign a confidence score from 1-10.

Finding to analyze:
```json
{finding_json}
```
{file_content}

Respond with EXACTLY this JSON structure:
{{
  "original_severity": "HIGH",
  "confidence_score": 8,
  "keep_finding": true,
  "exclusion_reason": null,
  "justification": "Explanation here"
}}"""

    def _read_file(self, file_path: str) -> Tuple[bool, str, str]:
        try:
            repo_path = os.environ.get('REPO_PATH')
            if repo_path:
                path = Path(file_path)
                if not path.is_absolute():
                    path = Path(repo_path) / file_path
            else:
                path = Path(file_path)
            
            if not path.exists() or not path.is_file():
                return False, "", f"File not found or not a file: {path}"
            
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except UnicodeDecodeError:
                with open(path, 'r', encoding='latin-1') as f:
                    content = f.read()
            return True, content, ""
        except Exception as e:
            return False, "", str(e)


# Alias for backward compatibility if needed, but we'll use factory mostly
class ClaudeAPIClient(BaseLLMClient):
    """Client for Anthropic's Claude API."""
    
    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, api_base: Optional[str] = None, **kwargs):
        # api_base ignored for Anthropic usually, but keeping signature compatible
        super().__init__(model=model, api_key=api_key or os.environ.get("ANTHROPIC_API_KEY"), **kwargs)
        if not self.model:
            self.model = DEFAULT_CLAUDE_MODEL
        if not self.api_key:
            raise ValueError("No Anthropic API key found.")
        if not Anthropic:
            raise ImportError("Anthropic package is not installed.")
        self.client = Anthropic(api_key=self.api_key)
        
    def validate_api_access(self) -> Tuple[bool, str]:
        try:
            self.client.messages.create(
                model="claude-3-5-haiku-20241022",
                max_tokens=10,
                messages=[{"role": "user", "content": "Hello"}],
                timeout=10
            )
            return True, ""
        except Exception as e:
            return False, str(e)

    def call_with_retry(self, prompt: str, system_prompt: Optional[str] = None, max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        try:
            return self._internal_call(prompt, system_prompt, max_tokens)
        except Exception as e:
            logger.error(f"Claude API failed: {e}")
            return False, "", str(e)

    @retry(stop=stop_after_attempt(5), wait=wait_exponential(multiplier=1, min=4, max=60), before_sleep=before_sleep_log(logger, logging.WARNING))

    def _internal_call(self, prompt: str, system_prompt: Optional[str] = None, max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        self._check_circuit_breaker()
        api_params = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "timeout": self.timeout_seconds
        }
        if system_prompt:
            api_params["system"] = system_prompt
        
        try:
            response = self.client.messages.create(**api_params)
            text = "".join([b.text for b in response.content if hasattr(b, 'text')])
            self._record_success()
            return True, text, ""
        except Exception as e:
            self._record_failure()
            raise e


class OpenAIClient(BaseLLMClient):
    """Client for OpenAI-compatible APIs."""
    
    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, api_base: Optional[str] = None, **kwargs):
        # Set defaults if not provided
        model = model or DEFAULT_OPENAI_MODEL
        api_key = api_key or os.environ.get("OPENAI_API_KEY")
        # api_base argument takes precedence over environment variable
        api_base = api_base or os.environ.get("OPENAI_API_BASE")
        
        super().__init__(model=model, api_key=api_key, api_base=api_base, **kwargs)
        
        if not self.api_key:
            self.api_key = "dummy"
            
        if not OpenAI:
            raise ImportError("OpenAI package is not installed. Please install it with `pip install openai`.")
            
        # Ensure base_url is passed if provided
        client_args = {"api_key": self.api_key}
        if self.api_base:
            client_args["base_url"] = self.api_base
            
        self.client = OpenAI(**client_args)

    def validate_api_access(self) -> Tuple[bool, str]:
        try:
            self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10
            )
            return True, ""
        except Exception as e:
            return False, str(e)

    def call_with_retry(self, prompt: str, system_prompt: Optional[str] = None, max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        try:
            return self._internal_call(prompt, system_prompt, max_tokens)
        except Exception as e:
            logger.error(f"OpenAI API failed: {e}")
            return False, "", str(e)

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=30), before_sleep=before_sleep_log(logger, logging.WARNING))

    def _internal_call(self, prompt: str, system_prompt: Optional[str] = None, max_tokens: int = PROMPT_TOKEN_LIMIT) -> Tuple[bool, str, str]:
        self._check_circuit_breaker()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens,
                timeout=self.timeout_seconds
            )
            text = response.choices[0].message.content
            self._record_success()
            return True, text, ""
        except Exception as e:
            self._record_failure()
            raise e


def get_llm_client(provider: str = 'anthropic',
                   model: Optional[str] = None,
                   api_key: Optional[str] = None,
                   api_base: Optional[str] = None,
                   timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> BaseLLMClient:
    """Factory to get the appropriate LLM client."""
    provider = provider.lower()
    
    if provider == 'openai' or provider == 'custom':
        return OpenAIClient(model=model, api_key=api_key, api_base=api_base, timeout_seconds=timeout_seconds)
    else:
        # Default to Claude/Anthropic
        return ClaudeAPIClient(model=model, api_key=api_key, timeout_seconds=timeout_seconds)

# Backwards compatibility for code expecting get_claude_api_client
def get_claude_api_client(model: str = DEFAULT_CLAUDE_MODEL,
                         api_key: Optional[str] = None,
                         timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> ClaudeAPIClient:
    return ClaudeAPIClient(model=model, api_key=api_key, timeout_seconds=timeout_seconds)
