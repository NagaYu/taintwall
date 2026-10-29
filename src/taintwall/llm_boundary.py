"""Bridge LLM tool proposals through deterministic attribution and an executor."""

from typing import Protocol, Sequence

from taintwall.attribution import UserIntent, attribute_arguments, plan_segment
from taintwall.boundary import ExecutionResult, GuardedExecutor
from taintwall.llm_client import ToolCallProposal
from taintwall.policy import REQUIRE_APPROVAL, ToolCall
from taintwall.provenance import Segment
from taintwall.runner import UnguardedExecutor


class Executor(Protocol):
    def execute(self, call: ToolCall, *, approve: bool = False) -> ExecutionResult: ...


class AttributingExecutor:
    def __init__(self, executor: GuardedExecutor | UnguardedExecutor) -> None:
        self.executor = executor

    def handle(
        self,
        proposal: ToolCallProposal,
        step_segments: Sequence[Sequence[Segment]],
        intent: UserIntent,
    ) -> str:
        if not step_segments:
            raise ValueError("step_segments must include the current planning step")
        current_step_index = len(step_segments) - 1
        current_segments = step_segments[current_step_index]
        tool_call = ToolCall(
            tool=proposal.tool,
            arguments=attribute_arguments(proposal, current_segments),
            initiated_by=plan_segment(step_segments, current_step_index),
            user_authorized_tools=intent.authorized_tools,
            user_explicit_recipients=intent.explicit_recipients,
        )
        result = self.executor.execute(tool_call)
        if result.executed:
            return result.output or ""
        if result.decision.action == REQUIRE_APPROVAL:
            return "Tool call not executed: approval is required."
        policy_ids = ", ".join(result.decision.fired_policies)
        if policy_ids:
            return f"Tool call blocked by policy: {policy_ids}."
        return "Tool call blocked by policy."
