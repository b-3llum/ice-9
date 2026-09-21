"""TARS autonomous agent loop with planning, execution, and reflection.

Implements a Plan → Execute → Reflect cycle:
  1. Planner decomposes the goal into subtasks.
  2. Executor runs tools and queries the LLM iteratively.
  3. Reflector evaluates answer quality and triggers retries.
  4. Memory records episodes for future reference.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ice_9.ai.llm import LLMClient
from ice_9.ai.memory import MemoryManager
from ice_9.ai.prompts.agent_system import (
    TARS_PLANNER_PROMPT,
    TARS_REFLECTOR_PROMPT,
    build_system_prompt,
)
from ice_9.ai.router import ModelRouter, TaskComplexity
from ice_9.tools.schema import ToolSchemaRegistry

# ------------------------------------------------------------------
# Data types
# ------------------------------------------------------------------

class StepType(str, Enum):
    THINK = "think"
    TOOL_CALL = "tool_call"
    ANSWER = "answer"
    ERROR = "error"


@dataclass
class Step:
    """A single step in the agent's execution trace."""

    type: StepType
    content: str
    tool_name: str = ""
    tool_args: dict[str, Any] = field(default_factory=dict)
    tool_result: str = ""
    duration_ms: float = 0
    model_used: str = ""
    provider_used: str = ""


@dataclass
class TaskResult:
    """Aggregated result of an agent run."""

    goal: str
    steps: list[Step] = field(default_factory=list)
    final_answer: str = ""
    success: bool = False
    iterations: int = 0
    total_duration_ms: float = 0


# ------------------------------------------------------------------
# Agent Loop
# ------------------------------------------------------------------

class AgentLoop:
    """Autonomous agent with planning, tool execution, and self-reflection.

    Ties together the ModelRouter (which model to use), MemoryManager
    (what context to provide), and ToolSchemaRegistry (what the LLM
    can invoke) into a single run loop.
    """

    MAX_ITERATIONS: int = 15
    MAX_RETRIES: int = 2

    def __init__(
        self,
        llm: LLMClient,
        router: ModelRouter,
        memory: MemoryManager,
        tool_registry: dict[str, Callable[..., Any]],
        schema_registry: ToolSchemaRegistry,
        system_prompt: str = "",
    ) -> None:
        self.llm = llm
        self.router = router
        self.memory = memory
        self.tools = tool_registry
        self.schemas = schema_registry
        self.system_prompt = system_prompt or build_system_prompt(
            tool_descriptions=schema_registry.to_text_block(),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, goal: str, context: str = "") -> TaskResult:
        """Execute a goal autonomously and return the result.

        Args:
            goal: Natural-language objective.
            context: Additional context (campaign data, etc.).

        Returns:
            TaskResult with steps taken, final answer, and success flag.
        """
        result = TaskResult(goal=goal)
        start = time.time()

        # Augment context with memory
        memory_context = self.memory.build_context(goal)
        full_context = f"{context}\n\n{memory_context}".strip() if memory_context else context

        self.memory.working.add("user", goal)

        # --- Classify: does this need planning, or is it a direct question? ---
        complexity = self.router._score_complexity(goal)
        needs_planning = complexity.value in ("high", "critical") or any(
            kw in goal.lower()
            for kw in ("scan", "run", "execute", "exploit", "attack", "enumerate", "dump")
        )

        if needs_planning:
            plan = self._plan(goal, full_context)
            result.steps.append(Step(type=StepType.THINK, content=plan))
        else:
            plan = ""

        # --- Execute ---
        messages = self._build_messages(goal, full_context, plan)
        retries = 0

        for i in range(self.MAX_ITERATIONS):
            result.iterations = i + 1

            last_user_msg = messages[-1]["content"] if messages else goal
            decision = self.router.route(last_user_msg, full_context)

            try:
                t0 = time.time()
                response = self.llm.chat(
                    provider=decision.provider,
                    messages=messages,
                    model=decision.model,
                    temperature=0.7,
                    max_tokens=4096,
                )
                latency = (time.time() - t0) * 1000
                self.router.record_latency(decision.provider.name, latency)
            except Exception as e:
                result.steps.append(Step(type=StepType.ERROR, content=str(e)))
                if retries < self.MAX_RETRIES:
                    retries += 1
                    continue
                break

            self.memory.working.add("assistant", response.content)

            # Parse structured output
            thinking = self._parse_tag("thinking", response.content)
            tool_calls = self._parse_tool_calls(response.content)
            answer = self._parse_tag("answer", response.content)

            if thinking:
                result.steps.append(Step(
                    type=StepType.THINK,
                    content=thinking,
                    model_used=response.model,
                    provider_used=response.provider,
                ))

            # --- Tool calls ---
            if tool_calls:
                for tc in tool_calls:
                    tool_result = self._execute_tool(tc["tool"], tc.get("args", {}))
                    result.steps.append(Step(
                        type=StepType.TOOL_CALL,
                        content=f"Called {tc['tool']}",
                        tool_name=tc["tool"],
                        tool_args=tc.get("args", {}),
                        tool_result=tool_result,
                        model_used=response.model,
                        provider_used=response.provider,
                    ))
                    # Feed tool result back
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append({
                        "role": "user",
                        "content": f"Tool result from {tc['tool']}:\n{tool_result}",
                    })
                    self.memory.working.add("tool", tool_result, tool=tc["tool"])

            # --- Final answer ---
            elif answer:
                if self._should_reflect(answer, goal):
                    reflection = self._reflect(goal, answer)
                    if "RETRY" in reflection:
                        result.steps.append(Step(
                            type=StepType.THINK,
                            content=f"Reflection: {reflection}",
                        ))
                        messages.append({"role": "assistant", "content": response.content})
                        messages.append({
                            "role": "user",
                            "content": (
                                f"Self-reflection: {reflection}\n"
                                "Please try again with improvements."
                            ),
                        })
                        retries += 1
                        if retries > self.MAX_RETRIES:
                            result.final_answer = answer
                            result.success = True
                            break
                        continue

                result.final_answer = answer
                result.success = True
                break

            # --- Unstructured response ---
            else:
                # If the model produced a substantive response without tags,
                # treat it as the final answer rather than looping forever.
                # Small local models often skip structured output.
                stripped = response.content.strip()
                if stripped and len(stripped) > 20:
                    result.final_answer = stripped
                    result.success = True
                    break

                # Very short / empty — ask for continuation
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": (
                        "Continue. If you're done, wrap your final answer "
                        "in <answer> tags."
                    ),
                })

        # --- Post-run bookkeeping ---
        result.total_duration_ms = (time.time() - start) * 1000

        self.memory.episodic.record(
            task=goal,
            actions=[s.content for s in result.steps],
            outcome=result.final_answer[:500] if result.final_answer else "No answer produced",
            success=result.success,
            lesson=self._extract_lesson(result) if not result.success else "",
        )

        if self.memory.working.should_summarize():
            summary = self._summarize_conversation()
            self.memory.working.compress(summary)

        return result

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------

    def _plan(self, goal: str, context: str) -> str:
        """Decompose the goal into 2-5 concrete subtasks."""
        plan_prompt = (
            f"Break down this goal into 2-5 concrete steps. "
            f"Be specific about what tools to use.\n\n"
            f"Goal: {goal}\n\n"
            f"Available tools: {', '.join(self.tools.keys())}\n\n"
            f"Output a numbered list of steps."
        )
        decision = self.router.route(
            plan_prompt, context, min_quality=TaskComplexity.MEDIUM,
        )
        messages = [
            {"role": "system", "content": TARS_PLANNER_PROMPT},
            {"role": "user", "content": plan_prompt},
        ]
        response = self.llm.chat(
            decision.provider, messages, model=decision.model, temperature=0.3,
        )
        return response.content

    # ------------------------------------------------------------------
    # Reflection
    # ------------------------------------------------------------------

    def _reflect(self, goal: str, answer: str) -> str:
        """Self-evaluate answer quality using the Reflector prompt."""
        reflect_prompt = (
            f"Evaluate this answer for the given goal. "
            f"Is it complete, accurate, and actionable?\n\n"
            f"Goal: {goal}\n"
            f"Answer: {answer[:1000]}\n\n"
            f"If the answer is good, say 'APPROVED'. "
            f"If it needs improvement, say 'RETRY: <reason>'."
        )
        decision = self.router.route(reflect_prompt)
        messages = [
            {"role": "system", "content": TARS_REFLECTOR_PROMPT},
            {"role": "user", "content": reflect_prompt},
        ]
        response = self.llm.chat(
            decision.provider, messages, model=decision.model, temperature=0.2,
        )
        return response.content

    def _should_reflect(self, answer: str, goal: str) -> bool:
        """Only reflect on non-trivial answers."""
        return len(answer) > 200 and len(goal.split()) > 5

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(self, name: str, args: dict[str, Any]) -> str:
        """Execute a registered tool and return its output (capped)."""
        if name not in self.tools:
            return (
                f"Error: tool '{name}' not found. "
                f"Available: {list(self.tools.keys())}"
            )

        # Safety: check if schema requires confirmation
        schema = self.schemas.get(name)
        if schema and schema.requires_confirmation:
            return (
                f"[CONFIRMATION REQUIRED] Tool '{name}' requires operator approval. "
                f"Args: {json.dumps(args)}"
            )

        try:
            result = self.tools[name](**args)
            output = str(result)
            # Cap output to avoid blowing up context
            if len(output) > 5000:
                output = output[:5000] + "\n... (truncated)"
            return output
        except Exception as e:
            return f"Error executing {name}: {e}"

    # ------------------------------------------------------------------
    # Message building
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        goal: str,
        context: str,
        plan: str,
    ) -> list[dict[str, str]]:
        """Assemble the initial message list for the execution loop."""
        messages: list[dict[str, str]] = [
            {"role": "system", "content": self.system_prompt},
        ]
        # Inject working memory (includes running summary if any)
        messages.extend(self.memory.working.get_context())

        if context:
            messages.append({"role": "user", "content": f"Context:\n{context}"})
            messages.append({
                "role": "assistant",
                "content": "Understood. I have the context.",
            })

        if plan:
            messages.append({
                "role": "user",
                "content": (
                    f"Goal: {goal}\n\nPlan:\n{plan}\n\n"
                    "Execute the plan step by step."
                ),
            })
        else:
            messages.append({
                "role": "user",
                "content": goal,
            })
        return messages

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_tag(tag: str, text: str) -> str:
        """Extract content from <tag>...</tag> in LLM output."""
        match = re.search(
            rf"<{tag}>(.*?)</{tag}>", text, re.DOTALL,
        )
        return match.group(1).strip() if match else ""

    @staticmethod
    def _parse_tool_calls(text: str) -> list[dict[str, Any]]:
        """Extract JSON tool calls from <tool_call>...</tool_call> blocks."""
        calls: list[dict[str, Any]] = []
        for match in re.finditer(
            r"<tool_call>(.*?)</tool_call>", text, re.DOTALL,
        ):
            try:
                calls.append(json.loads(match.group(1).strip()))
            except json.JSONDecodeError:
                continue
        return calls

    # ------------------------------------------------------------------
    # Post-run helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_lesson(result: TaskResult) -> str:
        """Derive a lesson from a failed task run."""
        errors = [s.content for s in result.steps if s.type == StepType.ERROR]
        if errors:
            return f"Failed due to: {errors[-1]}"
        return "Task did not complete within iteration limit"

    def _summarize_conversation(self) -> str:
        """Use the LLM to compress working memory into a summary."""
        msgs = self.memory.working.get_context()
        text = "\n".join(
            f"{m['role']}: {m['content'][:200]}" for m in msgs[-10:]
        )
        decision = self.router.route("summarize conversation")
        response = self.llm.chat(
            decision.provider,
            [
                {
                    "role": "system",
                    "content": "Summarize this conversation in 3-5 sentences.",
                },
                {"role": "user", "content": text},
            ],
            model=decision.model,
            temperature=0.2,
            max_tokens=500,
        )
        return response.content
