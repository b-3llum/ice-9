"""TARS prompt templates for local and cloud models."""

from ice_9.ai.prompts.agent_system import (
    TARS_BASE_PROMPT,
    TARS_PERSONALITY,
    TARS_PLANNER_PROMPT,
    TARS_REFLECTOR_PROMPT,
    build_system_prompt,
)

__all__ = [
    "TARS_BASE_PROMPT",
    "TARS_PERSONALITY",
    "TARS_PLANNER_PROMPT",
    "TARS_REFLECTOR_PROMPT",
    "build_system_prompt",
]
