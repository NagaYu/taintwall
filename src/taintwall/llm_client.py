"""LLM client abstractions with a fake implementation and lazy Anthropic SDK loading."""

import copy
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence


DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5-20251001"


@dataclass(frozen=True)
class ToolCallProposal:
    tool: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMResponse:
    text: str | None = None
    tool_calls: list[ToolCallProposal] = field(default_factory=list)


class LLMClient(ABC):
    @abstractmethod
    def complete(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[dict[str, Any]],
        system: str | None = None,
    ) -> LLMResponse:
        """Return either assistant text or one or more structured tool proposals."""


class FakeLLMClient(LLMClient):
    """Offline scripted client for tests; it never imports or calls an SDK."""

    def __init__(self, responses: Sequence[LLMResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []
        self._next_response = 0

    def complete(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[dict[str, Any]],
        system: str | None = None,
    ) -> LLMResponse:
        self.calls.append(
            {
                "messages": copy.deepcopy(list(messages)),
                "tools": copy.deepcopy(list(tools)),
                "system": system,
            }
        )
        if self._next_response >= len(self._responses):
            raise RuntimeError("FakeLLMClient response script is exhausted")
        response = copy.deepcopy(self._responses[self._next_response])
        self._next_response += 1
        return response


def _read_api_key_from_dotenv() -> str | None:
    """Read only ANTHROPIC_API_KEY from the local .env without printing its value."""

    direct_value = os.environ.get("ANTHROPIC_API_KEY")
    if direct_value:
        return direct_value

    env_file = Path(".env")
    if not env_file.is_file():
        return None
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() != "ANTHROPIC_API_KEY":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        return value or None
    return None


class AnthropicClient(LLMClient):
    """Anthropic Messages API adapter; SDK import and API access are call-time only."""

    def __init__(
        self,
        model: str = DEFAULT_ANTHROPIC_MODEL,
        *,
        max_tokens: int = 1024,
    ) -> None:
        self.model = model
        self.max_tokens = max_tokens
        self._client: Any | None = None
        self.usage_totals = {"input_tokens": 0, "output_tokens": 0}

    def complete(
        self,
        messages: Sequence[dict[str, Any]],
        tools: Sequence[dict[str, Any]],
        system: str | None = None,
    ) -> LLMResponse:
        try:
            import anthropic
        except ImportError as exc:
            raise RuntimeError(
                'Anthropic support requires the optional dependency: pip install -e ".[llm]"'
            ) from exc

        if self._client is None:
            api_key = _read_api_key_from_dotenv()
            if not api_key:
                raise RuntimeError("ANTHROPIC_API_KEY was not found in the environment or .env")
            self._client = anthropic.Anthropic(api_key=api_key)

        request = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0,
            "messages": list(messages),
            "tools": list(tools),
        }
        if system is not None:
            request["system"] = system
        response = self._client.messages.create(**request)
        usage = getattr(response, "usage", None)
        if usage is not None:
            self.usage_totals["input_tokens"] += int(getattr(usage, "input_tokens", 0))
            self.usage_totals["output_tokens"] += int(getattr(usage, "output_tokens", 0))
        text_blocks: list[str] = []
        proposals: list[ToolCallProposal] = []
        for block in response.content:
            if block.type == "text":
                text_blocks.append(block.text)
            elif block.type == "tool_use":
                proposals.append(
                    ToolCallProposal(
                        tool=block.name,
                        arguments=dict(block.input),
                    )
                )
        text = "\n".join(text_blocks) if text_blocks else None
        return LLMResponse(text=text, tool_calls=proposals)
