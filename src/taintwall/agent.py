"""SIMULATED deterministic agent for measuring policy enforcement, not LLM robustness."""

from dataclasses import dataclass, replace

from taintwall.boundary import ExecutionResult, GuardedExecutor
from taintwall.environments import VisibleContent
from taintwall.policy import ToolCall
from taintwall.provenance import Origin, Segment, derive


@dataclass(frozen=True)
class PlannedAction:
    tool: str
    argument_texts: dict[str, str]
    user_authorized_tools: frozenset[str] = frozenset()
    user_explicit_recipients: frozenset[str] = frozenset()


class ScriptedAgent:
    """SIMULATED actor with fixed rules; it does not model real LLM robustness."""

    def propose(
        self,
        user_task: PlannedAction,
        visible: list[VisibleContent],
        spotlighted_ids: set[str],
    ) -> list[ToolCall]:
        proposals = [self._user_proposal(user_task)]
        for content_index, content in enumerate(visible):
            directive = content.directive
            if directive is None or content.segment.id in spotlighted_ids:
                continue

            arguments: dict[str, Segment] = {}
            for argument_name, argument_text in directive.argument_texts.items():
                argument = derive(
                    new_text=argument_text,
                    sources=[content.segment],
                    new_id=f"{content.segment.id}:directive:{content_index}:{argument_name}",
                    origin=content.segment.origin,
                )
                extra_labels = directive.argument_labels.get(argument_name, frozenset())
                if extra_labels:
                    argument = replace(
                        argument,
                        labels=argument.labels.union(extra_labels),
                    )
                arguments[argument_name] = argument

            proposals.append(
                ToolCall(
                    tool=directive.tool,
                    arguments=arguments,
                    initiated_by=content.segment,
                    user_authorized_tools=user_task.user_authorized_tools,
                    user_explicit_recipients=user_task.user_explicit_recipients,
                )
            )
        return proposals

    def run(
        self,
        executor: GuardedExecutor,
        user_task: PlannedAction,
        visible: list[VisibleContent],
        spotlighted_ids: set[str],
    ) -> list[ExecutionResult]:
        return [
            executor.execute(call)
            for call in self.propose(user_task, visible, spotlighted_ids)
        ]

    @staticmethod
    def _user_proposal(user_task: PlannedAction) -> ToolCall:
        arguments = {
            name: Segment(
                id=f"user-task:{name}",
                text=text,
                origin=Origin.USER,
            )
            for name, text in user_task.argument_texts.items()
        }
        initiated_by = Segment(
            id="user-task:initiator",
            text=f"User requested tool {user_task.tool}.",
            origin=Origin.USER,
        )
        return ToolCall(
            tool=user_task.tool,
            arguments=arguments,
            initiated_by=initiated_by,
            user_authorized_tools=user_task.user_authorized_tools,
            user_explicit_recipients=user_task.user_explicit_recipients,
        )
