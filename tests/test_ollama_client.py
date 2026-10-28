import pytest

from taintgate.llm_client import ToolCallProposal
from taintgate.ollama_client import OllamaClient


def test_ollama_request_translation_tool_calls_and_usage_accumulation() -> None:
    captured: list[tuple[str, dict[str, object]]] = []
    responses = [
        {
            "message": {
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "read_file",
                            "arguments": {"path": "notes.txt"},
                        }
                    },
                    {
                        "function": {
                            "name": "send_email",
                            "arguments": '{"to":"friend@example.test","body":"Hi"}',
                        }
                    },
                ],
            },
            "prompt_eval_count": 13,
            "eval_count": 4,
        },
        {
            "message": {"content": "Finished."},
            "prompt_eval_count": 7,
            "eval_count": 2,
        },
    ]

    def post_json(url: str, payload: dict[str, object]) -> dict[str, object]:
        captured.append((url, payload))
        return responses.pop(0)

    client = OllamaClient(model="local-test", base_url="http://localhost:11434/", post_json=post_json)
    tools = [
        {
            "name": "read_file",
            "description": "Read a local mock file.",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]

    response = client.complete(
        messages=[{"role": "user", "content": "Read notes."}],
        tools=tools,
        system="Stay within the mock workspace.",
    )
    second = client.complete(messages=[], tools=[])

    url, payload = captured[0]
    assert url == "http://localhost:11434/api/chat"
    assert payload["model"] == "local-test"
    assert payload["stream"] is False
    assert payload["options"] == {"temperature": 0}
    assert payload["messages"][0] == {
        "role": "system",
        "content": "Stay within the mock workspace.",
    }
    assert payload["tools"] == [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a local mock file.",
                "parameters": tools[0]["input_schema"],
            },
        }
    ]
    assert response.text is None
    assert response.tool_calls == [
        ToolCallProposal("read_file", {"path": "notes.txt"}),
        ToolCallProposal(
            "send_email",
            {"to": "friend@example.test", "body": "Hi"},
        ),
    ]
    assert second.text == "Finished."
    assert client.usage_totals == {"input_tokens": 20, "output_tokens": 6}


@pytest.mark.parametrize(
    "post, message",
    [
        (lambda url, payload: (_ for _ in ()).throw(OSError("connection refused")), "request failed"),
        (lambda url, payload: {"message": {"tool_calls": "invalid"}}, "tool_calls must be a list"),
        (
            lambda url, payload: {
                "message": {
                    "tool_calls": [
                        {"function": {"name": "read_file", "arguments": "not-json"}}
                    ]
                }
            },
            "arguments are invalid JSON",
        ),
        (lambda url, payload: {"missing": "message"}, "missing a message object"),
    ],
)
def test_ollama_connection_and_format_errors_raise_runtime_error(post, message: str) -> None:
    client = OllamaClient(post_json=post)

    with pytest.raises(RuntimeError, match=message):
        client.complete(messages=[], tools=[])
