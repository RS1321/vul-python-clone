"""
LLM Client Wrapper

Supports multiple LLM providers: OpenRouter, DeepSeek, and Ollama
"""

import os
import requests
import json
import time
import re
from typing import List, Dict, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class LLMClient:
    """Unified LLM client for multiple providers"""
    
    def __init__(self, provider: str = "openrouter", model: str = "openai/gpt-4o", temperature: float = 0.1, max_tokens: int = 4000, conversation_logger=None):
        """
        Initialize LLM client
        
        Args:
            provider: "openrouter", "deepseek", or "ollama"
            model: Model name (e.g., "openai/gpt-4o", "deepseek/deepseek-r1", "qwen3:4b")
            temperature: Sampling temperature
            max_tokens: Maximum response tokens
            conversation_logger: Optional ConversationLogger instance
        """
        self.provider = provider.lower()
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.conversation_logger = conversation_logger
        
        # Get API keys from environment
        self.openrouter_key = os.getenv("OPENROUTER_API_KEY")
        self.deepseek_key = os.getenv("DEEPSEEK_API_KEY")
        # Explicit Gemini-only alias: the user's Windows OPENAI_API_KEY is a
        # Gemini credential. Never send this value to OpenAI or OpenRouter.
        self.gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.site_url = os.getenv("SITE_URL", "https://github.com/Deep-Jiwan/remediator")
        self.site_name = os.getenv("SITE_NAME", "Security Remediator")
        
        # Validate configuration
        if self.provider == "openrouter" and not self.openrouter_key:
            raise ValueError("OPENROUTER_API_KEY not found in environment")
        elif self.provider == "deepseek" and not self.deepseek_key:
            raise ValueError("DEEPSEEK_API_KEY not found in environment")
        elif self.provider == "gemini" and not self.gemini_key:
            raise ValueError("Set GEMINI_API_KEY (or the configured OPENAI_API_KEY Gemini alias)")
        elif self.provider not in ["openrouter", "deepseek", "ollama", "gemini", "local"]:
            raise ValueError(f"Unsupported provider: {provider}")
    
    def chat_completion(self, messages: List[Dict[str, str]], system_prompt: Optional[str] = None, 
                       purpose: str = "chat", metrics=None, finding_number: Optional[str] = None, 
                       attempt_number: Optional[int] = None) -> Dict:
        """
        Send chat completion request to LLM provider
        
        Args:
            messages: List of message dicts with "role" and "content"
            system_prompt: Optional system prompt (prepended to messages)
            purpose: Purpose of this API call (for metrics tracking)
            metrics: Optional Metrics object to record API call
            finding_number: Optional finding number for logging
            attempt_number: Optional attempt number for logging
        
        Returns:
            API response dict with "content" and metadata
        """
        # Prepend system prompt if provided
        if system_prompt:
            messages = [{"role": "system", "content": system_prompt}] + messages
        
        # Track API call timing
        start_time = time.time()
        
        try:
            if self.provider == "openrouter":
                result = self._openrouter_request(messages)
            elif self.provider == "deepseek":
                result = self._deepseek_request(messages)
            elif self.provider == "ollama":
                result = self._ollama_request(messages)
            elif self.provider == "gemini":
                result = self._gemini_request(messages)
            elif self.provider == "local":
                result = self._local_request(messages)
        except Exception as e:
            # Log error if conversation logger is available
            if self.conversation_logger:
                self.conversation_logger.log_error(
                    error_message=str(e),
                    context={
                        'purpose': purpose,
                        'finding_number': finding_number,
                        'attempt_number': attempt_number,
                        'model': self.model
                    }
                )
            raise
        
        # Calculate duration
        duration_ms = (time.time() - start_time) * 1000
        
        # Record metrics if provided
        if metrics:
            usage = result.get("usage", {})
            metrics.record_api_call(
                call_type=self.provider,
                model=result.get("model", self.model),
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                total_tokens=usage.get("total_tokens", 0),
                duration_ms=duration_ms,
                purpose=purpose
            )
        
        # Log conversation if logger is available
        if self.conversation_logger:
            usage = result.get("usage", {})
            self.conversation_logger.log_conversation(
                messages=messages,
                response=result.get("content", ""),
                model=result.get("model", self.model),
                purpose=purpose,
                finding_number=finding_number,
                attempt_number=attempt_number,
                metadata={
                    'duration_ms': duration_ms,
                    'prompt_tokens': usage.get('prompt_tokens', 0),
                    'completion_tokens': usage.get('completion_tokens', 0),
                    'total_tokens': usage.get('total_tokens', 0)
                }
            )
        
        return result
    
    def _openrouter_request(self, messages: List[Dict[str, str]]) -> Dict:
        """Send request to OpenRouter API with retry logic for rate limiting"""
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.openrouter_key}",
            "HTTP-Referer": self.site_url,
            "X-OpenRouter-Title": self.site_name,
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        max_retries = 3
        base_delay = 5  # seconds
        
        for attempt in range(max_retries):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=120)
                response.raise_for_status()
                result = response.json()
                
                return {
                    "content": result["choices"][0]["message"]["content"],
                    "model": result.get("model", self.model),
                    "usage": result.get("usage", {}),
                    "provider": "openrouter"
                }
            except requests.exceptions.HTTPError as e:
                # Handle rate limiting (429) with exponential backoff
                if e.response.status_code == 429 and attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)  # Exponential backoff: 5s, 10s, 20s
                    print(f"    ⚠️  Rate limited by OpenRouter. Retrying in {delay}s... (attempt {attempt + 1}/{max_retries})")
                    time.sleep(delay)
                    continue
                else:
                    raise RuntimeError(f"OpenRouter API error: {str(e)}")
            except requests.exceptions.RequestException as e:
                raise RuntimeError(f"OpenRouter API error: {str(e)}")
    
    def _gemini_request(self, messages: List[Dict[str, str]]) -> Dict:
        """Native Gemini/Gemma API; no automatic model or paid-provider fallback."""
        from egress_guard import check_messages, sanitise
        messages=[dict(m,content=sanitise(m['content'])) for m in messages]
        check_messages(messages)
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", self.model):
            raise ValueError("Use an exact Gemini model ID, without models/ prefix")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        systems = [m['content'] for m in messages if m['role'] == 'system']
        contents = [{'role': 'model' if m['role'] == 'assistant' else 'user',
                     'parts': [{'text': m['content']}]} for m in messages if m['role'] != 'system']
        payload = {"contents": contents,
                   "generationConfig": {"temperature": self.temperature,
                                        "maxOutputTokens": self.max_tokens}}
        if systems:
            payload['systemInstruction'] = {'parts': [{'text': '\n\n'.join(systems)}]}
        if self.model.startswith('gemma-4-'):
            # Explicitly disable optional thinking for this free-model cohort.
            # This is recorded in each run; original/default-thinking pilots
            # are not pooled with these revised experiments.
            payload['generationConfig']['thinkingConfig'] = {'thinkingLevel': 'minimal'}
        transport_events = []
        retries=int(os.getenv('AVR_TRANSPORT_RETRIES','4'))
        timeout=int(os.getenv('AVR_REQUEST_TIMEOUT','120'))
        for attempt in range(retries):
            from request_budget import reserve
            waited=reserve(self.model,payload)
            try:
                response = requests.post(url, headers={"x-goog-api-key": self.gemini_key},
                                         json=payload, timeout=timeout)
            except requests.exceptions.RequestException as exc:
                raise RuntimeError(f'Gemini transport failure: {type(exc).__name__}') from None
            transport_events.append({'http_status': response.status_code,'budget_wait_seconds':waited})
            if response.status_code == 429 and attempt < retries-1:
                # Respect a short provider-supplied rate-limit delay. Daily limits
                # and prompts exceeding the per-request window remain failures.
                match = re.search(r'Please retry in ([0-9.]+)s', response.text)
                wait = float(match[1]) + 1 if match else None
                if wait is not None and wait <= 60:
                    transport_events[-1]['retry_wait_seconds'] = wait
                    time.sleep(wait)
                    continue
            if response.status_code not in (500, 502, 503, 504) or attempt == retries-1:
                break
            time.sleep(2 ** (attempt + 1))
        if response.status_code != 200:
            # Do not echo headers, credentials, or full request URLs to logs.
            detail = response.text.replace(self.gemini_key, "<redacted>")[:2000]
            raise RuntimeError(f"Gemini HTTP {response.status_code}: {detail}")
        data = response.json()
        reported_model = data.get('modelVersion', '').removeprefix('models/')
        if not (reported_model == self.model or reported_model.startswith(self.model + '-')):
            raise RuntimeError(f'Gemini model mismatch: requested {self.model}, reported {reported_model or "missing"}')
        candidate = (data.get("candidates") or [{}])[0]
        content = "".join(part.get("text", "") for part in candidate.get("content", {}).get("parts", [])
                          if not part.get("thought"))
        if not content or candidate.get("finishReason") not in (None, "STOP"):
            raise RuntimeError(f"Gemini returned incomplete/blocked output: {candidate.get('finishReason')}")
        usage = data.get("usageMetadata", {})
        return {"content": content, "model": reported_model,
                "provider": "gemini", "transport_events": transport_events, "usage": {
                    "prompt_tokens": usage.get("promptTokenCount", 0),
                    "completion_tokens": usage.get("candidatesTokenCount", 0) + usage.get("thoughtsTokenCount", 0),
                    "total_tokens": usage.get("totalTokenCount", 0)}}

    def _local_request(self, messages):
        """Free local models use fixed loopback-only, credential-free endpoints."""
        from egress_guard import sanitise
        messages=[dict(m,content=sanitise(m['content'])) for m in messages]
        ports={'qwen2.5-coder-1.5b-instruct-q4km':18080,
               'qwen2.5-coder-0.5b-instruct-q4km':18081}
        if self.model not in ports:
            raise ValueError('Local model requires an explicitly configured loopback port')
        with requests.Session() as session:
            session.trust_env=False
            try:
                response=session.post(f'http://127.0.0.1:{ports[self.model]}/v1/chat/completions',
                    json={'model':self.model,'messages':messages,'temperature':self.temperature,
                          'max_tokens':self.max_tokens},timeout=180)
                response.raise_for_status()
                data=response.json()
            except requests.RequestException as exc:
                raise RuntimeError(f'Local API error: {type(exc).__name__}') from None
        if data.get('model') != self.model:
            raise RuntimeError('Local API error: model identity mismatch')
        choice=data['choices'][0]
        if choice.get('finish_reason')!='stop':
            raise RuntimeError('Local API error: incomplete output')
        return {'content':choice['message']['content'],'model':self.model,
                'provider':'local','usage':data.get('usage',{})}

    def _deepseek_request(self, messages: List[Dict[str, str]]) -> Dict:
        """Send request to DeepSeek API"""
        url = "https://api.deepseek.com/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.deepseek_key}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=120)
            response.raise_for_status()
            result = response.json()
            
            return {
                "content": result["choices"][0]["message"]["content"],
                "model": result.get("model", self.model),
                "usage": result.get("usage", {}),
                "provider": "deepseek"
            }
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"DeepSeek API error: {str(e)}")
    
    def _ollama_request(self, messages: List[Dict[str, str]]) -> Dict:
        """Send request to Ollama API (local server)"""
        url = f"{self.ollama_url}/api/chat"
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens
            }
        }
        
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=300)
            response.raise_for_status()
            result = response.json()
            
            # Ollama response format: {"message": {"role": "assistant", "content": "..."}, "model": "qwen3:4b"}
            return {
                "content": result["message"]["content"],
                "model": result.get("model", self.model),
                "usage": {},  # Ollama doesn't provide token usage by default
                "provider": "ollama"
            }
        except requests.exceptions.ConnectionError:
            raise RuntimeError(f"Cannot connect to Ollama at {self.ollama_url}. Make sure Ollama is running (ollama serve)")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Ollama API error: {str(e)}")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"DeepSeek API error: {str(e)}")
    
    def get_fix(self, prompt: str, system_prompt: str, purpose: str = "get_fix", metrics=None, 
                finding_number: Optional[str] = None, attempt_number: Optional[int] = None) -> str:
        """
        Get vulnerability fix from LLM
        
        Args:
            prompt: User prompt with vulnerability details
            system_prompt: System prompt with instructions
            purpose: Purpose of this call (for metrics)
            metrics: Optional Metrics object to record API call
            finding_number: Optional finding number for logging
            attempt_number: Optional attempt number for logging
        
        Returns:
            LLM response content
        """
        messages = [{"role": "user", "content": prompt}]
        response = self.chat_completion(messages, system_prompt=system_prompt, 
                                       purpose=purpose, metrics=metrics,
                                       finding_number=finding_number, attempt_number=attempt_number)
        return response["content"]
    
    def get_model_name(self) -> str:
        """Get sanitized model name for branch naming"""
        # Extract model name parts (e.g., "openai/gpt-4o" -> "gpt-4o")
        # Replace special characters that are invalid in Windows paths
        if "/" in self.model:
            return self.model.split("/")[-1].replace(".", "-").replace(":", "-")
        return self.model.replace(".", "-").replace(":", "-")
    
    def get_provider_name(self) -> str:
        """Get provider name for branch naming"""
        return self.provider


def create_llm_client(config: Dict, conversation_logger=None) -> LLMClient:
    """
    Factory function to create LLM client from config
    
    Args:
        config: Configuration dict with llm settings
        conversation_logger: Optional ConversationLogger instance
    
    Returns:
        Configured LLMClient instance
    """
    llm_config = config.get("llm", {})
    return LLMClient(
        provider=llm_config.get("provider", "openrouter"),
        model=llm_config.get("model", "openai/gpt-4o"),
        temperature=llm_config.get("temperature", 0.1),
        max_tokens=llm_config.get("max_tokens", 4000),
        conversation_logger=conversation_logger
    )
