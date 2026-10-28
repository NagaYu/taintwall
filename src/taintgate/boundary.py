"""Policy-enforcing boundary for offline mock tool execution."""

from dataclasses import dataclass, replace

from taintgate.policy import (
    ALLOW,
    ALLOW_WITH_REDACTION,
    DESTINATION_ARGUMENTS,
    REQUIRE_APPROVAL,
    Decision,
    PolicyEngine,
    ToolCall,
)
from taintgate.tools import MockTools


@dataclass(frozen=True)
class ExecutionResult:
    decision: Decision
    executed: bool
    output: str | None


class GuardedExecutor:
    def __init__(self, policy_engine: PolicyEngine, mock_tools: MockTools) -> None:
        self.policy_engine = policy_engine
        self.mock_tools = mock_tools

    def execute(self, call: ToolCall, *, approve: bool = False) -> ExecutionResult:
        decision = self.policy_engine.evaluate(call)
        if decision.action not in {ALLOW, ALLOW_WITH_REDACTION, REQUIRE_APPROVAL}:
            return ExecutionResult(decision=decision, executed=False, output=None)
        if decision.action == REQUIRE_APPROVAL and not approve:
            return ExecutionResult(decision=decision, executed=False, output=None)

        arguments = dict(call.arguments)
        if decision.action == ALLOW_WITH_REDACTION:
            for name in decision.redaction_targets:
                arguments[name] = replace(arguments[name], text="[REDACTED]")

        text_arguments = {name: segment.text for name, segment in arguments.items()}
        self._normalize_destination(call.tool, text_arguments)
        output = self._invoke(call.tool, text_arguments)
        return ExecutionResult(decision=decision, executed=True, output=output)

    @staticmethod
    def _normalize_destination(tool: str, arguments: dict[str, str]) -> None:
        if tool not in {"send_email", "send_message", "http_post"}:
            return

        destination_name = "url" if tool == "http_post" else "to"
        present_names = [name for name in DESTINATION_ARGUMENTS if name in arguments]
        if present_names:
            destination = arguments[present_names[0]]
            for name in DESTINATION_ARGUMENTS:
                arguments.pop(name, None)
            arguments[destination_name] = destination

    def _invoke(self, tool: str, arguments: dict[str, str]) -> str:
        if tool == "send_email":
            return self.mock_tools.send_email(**arguments)
        if tool == "http_post":
            return self.mock_tools.http_post(**arguments)
        if tool == "send_message":
            return self.mock_tools.send_message(**arguments)
        if tool == "read_file":
            return self.mock_tools.read_file(**arguments)
        if tool == "write_file":
            return self.mock_tools.write_file(**arguments)
        if tool == "delete_file":
            return self.mock_tools.delete_file(**arguments)
        if tool == "purchase":
            return self.mock_tools.purchase(**arguments)
        if tool == "exec":
            return self.mock_tools.exec(**arguments)
        if tool == "memory_save":
            return self.mock_tools.memory_save(**arguments)
        raise ValueError(f"unknown mock tool: {tool}")
