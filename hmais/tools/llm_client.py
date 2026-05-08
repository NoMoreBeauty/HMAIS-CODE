
import json
from typing import Optional, Dict, Any
import config


def _make_client(model: str):
    """根据 config.LLM_PROVIDER 返回对应的调用后端实例。"""
    if config.LLM_PROVIDER == "openrouter":
        return _OpenRouterBackend(model)
    else:
        return _DashScopeBackend(model)


class _DashScopeBackend:

    def __init__(self, model: str):
        import dashscope
        from dashscope import Generation
        dashscope.api_key = config.DASHSCOPE_API_KEY
        self._Generation = Generation
        self.model = model

    def call(self, messages: list, temperature: float, max_tokens: int) -> str:
        response = self._Generation.call(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            result_format='message'
        )
        if response.status_code == 200:
            return response.output.choices[0].message.content
        raise RuntimeError(f"DashScope error {response.status_code}: {response.message}")


class _OpenRouterBackend:

    def __init__(self, model: str):
        from openai import OpenAI
        self._client = OpenAI(
            api_key=config.OPENROUTER_API_KEY,
            base_url=config.OPENROUTER_BASE_URL,
        )
        self.model = model

    def call(self, messages: list, temperature: float, max_tokens: int) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return response.choices[0].message.content


class LLMClient:

    def __init__(self, model: Optional[str] = None, temperature: Optional[float] = None):
        self.model = model or config.LLM_MODEL
        self.temperature = temperature if temperature is not None else config.LLM_TEMPERATURE
        self.max_tokens = config.LLM_MAX_TOKENS
        self._backend = _make_client(self.model)

    def call(
        self,
        system_prompt: str,
        user_message: str,
        temperature: Optional[float] = None,
        response_format: str = "text"
    ) -> str:
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
        try:
            result = self._backend.call(
                messages=messages,
                temperature=temperature if temperature is not None else self.temperature,
                max_tokens=self.max_tokens,
            )
            if response_format == "json":
                result = self._extract_json(result)
            return result
        except Exception as e:
            error_msg = f"LLM call exception: {str(e)}"
            print(f"⚠️  {error_msg}")
            return f"Error: {error_msg}"

    def _extract_json(self, text: str) -> str:
        if "```json" in text:
            start = text.find("```json") + 7
            end = text.find("```", start)
            if end != -1:
                return text[start:end].strip()
        elif "```" in text:
            start = text.find("```") + 3
            end = text.find("```", start)
            if end != -1:
                return text[start:end].strip()
        return text.strip()

    def call_json(
        self,
        system_prompt: str,
        user_message: str,
        temperature: Optional[float] = None
    ) -> Dict[str, Any]:
        result = self.call(system_prompt, user_message, temperature, response_format="json")
        try:
            return json.loads(result)
        except json.JSONDecodeError as e:
            print(f"⚠️  Failed to parse JSON response: {e}")
            print(f"Raw response: {result[:200]}...")
            return {"error": f"JSON parse error: {str(e)}", "raw_response": result}

    def call_json_with_raw(
        self,
        system_prompt: str,
        user_message: str,
        temperature: Optional[float] = None
    ) -> tuple[Dict[str, Any], str]:
        raw_result = self.call(system_prompt, user_message, temperature, response_format="json")
        try:
            return json.loads(raw_result), raw_result
        except json.JSONDecodeError as e:
            print(f"⚠️  Failed to parse JSON response: {e}")
            return {"error": f"JSON parse error: {str(e)}", "raw_response": raw_result}, raw_result

    def call_with_raw(
        self,
        system_prompt: str,
        user_message: str,
        temperature: Optional[float] = None
    ) -> tuple[str, str]:
        raw_result = self.call(system_prompt, user_message, temperature, response_format="text")
        return raw_result, raw_result
