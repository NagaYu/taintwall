"""Ollama chat API client using only the Python standard library."""

import json
from typing import Any, Callable, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from taintgate.llm_client import LLMClient, LLMResponse, ToolCallProposal


OLLAMA_DEFAULT_MODEL = "qwen2.5:7b"
OLLAMA_DEFAULT_BASE_URL = "http://localhost:11434"


def _urllib_post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=120) as response:
            parsed = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Ollama request failed: {exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("Ollama response must be a JSON object")
    return parsed


class OllamaClient(LLMClient):
    """LLMClient implementation for a local Ollama server; no external SDK is required."""

    def __init__(
        self,
        model: str = OLLAMA_DEFAULT_MODEL,
        base_url: str = OLLAMA_DEFAULT_BASE_URL,
        post_json: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.post_json = post_json or _urllib_post_json
        self.usage_totals = {"input_tokens": 0, "output_tokens": 0}

    @staticmethod
    def _ollama_tool(tool: dict[str, Any]) -> dict[str, Any]:
        if tool.get("type") == "function" and isinstance(tool.get("function"), dict):
            function = tool["function"]
            name = function.get("name")
            description = function.get("description", "")
            parameters = function.get("parameters", {"type": "object", "properties": {}})
        else:
            name = tool.get("name")
            description = tool.get("description", "")
            parameters = tool.get("input_schema", tool.get("parameters"))
        if not isinstance(name, str) or not isinstance(description, str):
            raise RuntimeError("ToolSpec must include string name and description fields")
        if not isinstance(parameters, dict):
            raise RuntimeError(f"ToolSpec {name!r} must include an object parameters schema")
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
        }

    def complete(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[dict[str, Any]],
        system: str | None = None,
    ) -> LLMResponse:
        conversation = list(messages)
        if system is not None:
            conversation.insert(0, {"role": "system", "content": system})
        payload = {
            "model": self.model,
            "messages": conversation,
            "stream": False,
            "options": {"temperature": 0},
            "tools": [self._ollama_tool(tool) for tool in tools],
        }
        try:
            response = self.post_json(f"{self.base_url}/api/chat", payload)
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise
            raise RuntimeError(f"Ollama request failed: {exc}") from exc
        if not isinstance(response, dict):
            raise RuntimeError("Ollama response must be a JSON object")
        message = response.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("Ollama response is missing a message object")
        content = message.get("content", "")
        if not isinstance(content, str):
            raise RuntimeError("Ollama message.content must be a string")
        raw_tool_calls = message.get("tool_calls", [])
        if not isinstance(raw_tool_calls, list):
            raise RuntimeError("Ollama message.tool_calls must be a list")

        proposals: list[ToolCallProposal] = []
        for raw_call in raw_tool_calls:
            if not isinstance(raw_call, dict):
                raise RuntimeError("Ollama tool call must be an object")
            function = raw_call.get("function")
            if not isinstance(function, dict) or not isinstance(function.get("name"), str):
                raise RuntimeError("Ollama tool call is missing function.name")
            arguments = function.get("arguments", {})
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError as exc:
                    raise RuntimeError("Ollama tool call arguments are invalid JSON") from exc
            if not isinstance(arguments, dict):
                raise RuntimeError("Ollama tool call arguments must be a JSON object")
            proposals.append(ToolCallProposal(function["name"], arguments))

        input_tokens = response.get("prompt_eval_count", 0)
        output_tokens = response.get("eval_count", 0)
        if (
            not isinstance(input_tokens, int)
            or input_tokens < 0
            or not isinstance(output_tokens, int)
            or output_tokens < 0
        ):
            raise RuntimeError("Ollama token usage counts must be non-negative integers")
        self.usage_totals["input_tokens"] += input_tokens
        self.usage_totals["output_tokens"] += output_tokens
        return LLMResponse(text=content or None, tool_calls=proposals)
