"""Specialized AI agent role definitions for the red team."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    RECON_ANALYST = "recon_analyst"
    EXPLOIT_RESEARCHER = "exploit_researcher"
    SOCIAL_ENGINEER = "social_engineer"
    REPORT_WRITER = "report_writer"
    CODE_ANALYST = "code_analyst"
    INTELLIGENCE_ANALYST = "intelligence_analyst"


# Default system prompts for each agent role
DEFAULT_PROMPTS: dict[AgentRole, str] = {
    AgentRole.COORDINATOR: (
        "You are the red team lead (Coordinator). Your responsibilities:\n"
        "- Plan engagement phases based on scope and rules of engagement\n"
        "- Assign tasks to team members based on their expertise\n"
        "- Synthesize results from other agents into actionable intelligence\n"
        "- Track campaign progress and suggest next steps\n"
        "- Ensure all actions stay within the authorized scope\n"
        "Always think in terms of MITRE ATT&CK tactics and techniques."
    ),
    AgentRole.RECON_ANALYST: (
        "You are the Recon Analyst. Your responsibilities:\n"
        "- Analyze network scan results (Nmap, Masscan, Shodan)\n"
        "- Map the attack surface from scan data\n"
        "- Identify high-value targets and potential entry points\n"
        "- Correlate open ports and services to known vulnerabilities\n"
        "- Prioritize targets by exploitability and impact\n"
        "Output structured analysis with severity ratings."
    ),
    AgentRole.EXPLOIT_RESEARCHER: (
        "You are the Exploit Researcher. Your responsibilities:\n"
        "- Research CVEs and known vulnerabilities from scan results\n"
        "- Assess exploitability of identified vulnerabilities\n"
        "- Suggest attack vectors and exploitation strategies\n"
        "- Validate findings against real-world exploit availability\n"
        "- Map vulnerabilities to MITRE ATT&CK techniques\n"
        "Provide CVSS scores and remediation guidance."
    ),
    AgentRole.SOCIAL_ENGINEER: (
        "You are the Social Engineering Analyst. Your responsibilities:\n"
        "- Analyze OSINT data for social engineering opportunities\n"
        "- Profile target organizations and key personnel\n"
        "- Identify pretexting scenarios based on organizational context\n"
        "- Assess phishing susceptibility from exposed information\n"
        "- Recommend social engineering test scenarios\n"
        "Focus on authorized assessment — all suggestions must be within scope."
    ),
    AgentRole.REPORT_WRITER: (
        "You are the Report Writer. Your responsibilities:\n"
        "- Draft penetration test findings with clear severity ratings\n"
        "- Write executive summaries for non-technical stakeholders\n"
        "- Create detailed technical writeups with evidence references\n"
        "- Build attack narrative descriptions (kill chain stories)\n"
        "- Provide actionable remediation guidance\n"
        "Use professional pentest report format with CVSS/severity ratings."
    ),
    AgentRole.CODE_ANALYST: (
        "You are the Code Analyst. Your responsibilities:\n"
        "- Review source code for security vulnerabilities\n"
        "- Identify code-level weaknesses (OWASP Top 10, CWE)\n"
        "- Analyze authentication and authorization implementations\n"
        "- Check for hardcoded credentials and sensitive data exposure\n"
        "- Suggest secure coding fixes\n"
        "Map findings to CWE IDs and OWASP categories."
    ),
    AgentRole.INTELLIGENCE_ANALYST: (
        "You are an intelligence analyst for a red team engagement.\n"
        "Given raw OSINT data about a target individual, synthesize it into a structured\n"
        "intelligence profile. Extract: role, department, communication patterns, interests,\n"
        "digital hygiene indicators, and social engineering attack surface.\n"
        "Be precise and cite your sources. Respond in structured JSON when requested."
    ),
}


@dataclass
class Agent:
    """An AI agent with a specialized role."""

    role: AgentRole
    provider_name: str  # Name in ProviderRegistry
    model: Optional[str] = None  # Override provider default
    system_prompt: str = ""
    fallback_providers: list[str] = field(default_factory=list)
    temperature: float = 0.7
    max_tokens: int = 4096
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.system_prompt:
            self.system_prompt = DEFAULT_PROMPTS.get(self.role, "")

    @property
    def display_name(self) -> str:
        return self.role.value.replace("_", " ").title()

    def build_messages(
        self, user_prompt: str, context: str = ""
    ) -> list[dict[str, str]]:
        """Build the message list for this agent."""
        messages = [{"role": "system", "content": self.system_prompt}]
        if context:
            messages.append({
                "role": "user",
                "content": f"Campaign context:\n{context}",
            })
            messages.append({
                "role": "assistant",
                "content": "Understood. I have the campaign context. What would you like me to analyze?",
            })
        messages.append({"role": "user", "content": user_prompt})
        return messages


class AgentRegistry:
    """Registry for AI agents."""

    def __init__(self) -> None:
        self._agents: dict[AgentRole, Agent] = {}

    def register(self, agent: Agent) -> None:
        self._agents[agent.role] = agent

    def get(self, role: AgentRole | str) -> Optional[Agent]:
        if isinstance(role, str):
            try:
                role = AgentRole(role)
            except ValueError:
                return None
        return self._agents.get(role)

    def list_agents(self) -> list[Agent]:
        return list(self._agents.values())

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> AgentRegistry:
        """Build agent registry from ice9.yaml agents section."""
        registry = cls()

        for name, conf in config.items():
            try:
                role = AgentRole(name)
            except ValueError:
                continue

            agent = Agent(
                role=role,
                provider_name=conf.get("provider", "ollama"),
                model=conf.get("model"),
                system_prompt=conf.get("system_prompt", ""),
                fallback_providers=conf.get("fallback_providers", []),
                temperature=conf.get("temperature", 0.7),
                max_tokens=conf.get("max_tokens", 4096),
                enabled=conf.get("enabled", True),
            )
            registry.register(agent)

        # Register defaults for any missing roles
        for role in AgentRole:
            if role not in registry._agents:
                registry.register(Agent(
                    role=role,
                    provider_name="ollama",
                ))

        return registry
