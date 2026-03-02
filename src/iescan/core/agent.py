"""Agentic pentest orchestrator.

Autonomous agent that iteratively runs assessment modules,
uses LLM reasoning to decide next steps, and builds a comprehensive
picture of the enterprise attack surface.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from iescan.config import ScanConfig
from iescan.core.reasoning import ReasoningConfig, ReasoningEngine
from iescan.core.scanner import (
    BaseModule,
    ModuleResult,
    ScanEngine,
    ScanResult,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass
class AgentStep:
    """A single step in the agent's execution."""

    step_number: int
    module_name: str
    target: str
    reasoning: str
    result: ModuleResult | None = None
    duration_seconds: float = 0.0


@dataclass
class AgentSession:
    """Complete agent session with all steps and reasoning."""

    engagement_id: str
    steps: list[AgentStep] = field(default_factory=list)
    cross_correlations: list[dict[str, Any]] = field(default_factory=list)
    attack_narrative: str = ""
    executive_summary: str = ""
    total_findings: int = 0


class PentestAgent:
    """Autonomous pentesting agent that uses LLM reasoning to guide assessments.

    The agent:
    1. Starts with network discovery
    2. Analyzes results and decides which module to run next
    3. Correlates findings across modules
    4. Identifies compound attack paths
    5. Generates comprehensive reporting with attack narratives
    """

    def __init__(
        self,
        scan_config: ScanConfig,
        reasoning_config: ReasoningConfig,
        max_steps: int = 20,
    ) -> None:
        self.scan_config = scan_config
        self.reasoning = ReasoningEngine(reasoning_config)
        self.max_steps = max_steps
        self.engine = ScanEngine(scan_config)
        self.session = AgentSession(engagement_id=scan_config.engagement_id)
        self.completed_results: list[ModuleResult] = []

        # All available modules
        self._available_modules: dict[str, type[BaseModule]] = {}
        self._modules_run: set[str] = set()

    def register_modules(self, modules: dict[str, type[BaseModule]]) -> None:
        """Register all available assessment modules."""
        self._available_modules = modules

    def run(self, initial_targets: list[str]) -> AgentSession:
        """Run the agentic assessment loop."""
        logger.info("Starting agentic assessment with %d initial targets", len(initial_targets))

        # Step 1: Always start with network discovery
        for target in initial_targets:
            if "network_discovery" in self._available_modules:
                self._execute_step(
                    "network_discovery",
                    target,
                    "Starting with network discovery to map the attack surface.",
                )

        # Step 2: Iterative reasoning loop
        step = len(self.session.steps)
        while step < self.max_steps:
            remaining = [
                name
                for name in self._available_modules
                if name not in self._modules_run
            ]

            if not remaining:
                logger.info("All modules have been run.")
                break

            # Ask the reasoning engine what to do next
            try:
                decision = self.reasoning.decide_next_module(
                    self.completed_results, remaining
                )
            except Exception as e:
                logger.error("Reasoning engine error: %s", e)
                # Fallback: run modules in order
                decision = {
                    "next_module": remaining[0],
                    "target": initial_targets[0],
                    "reasoning": f"Fallback execution (reasoning error: {e})",
                }

            next_module = decision.get("next_module", "")
            target = decision.get("target", initial_targets[0])
            reasoning = decision.get("reasoning", "")

            if next_module not in self._available_modules:
                logger.warning("Reasoning suggested unknown module: %s", next_module)
                break

            priority = decision.get("priority", "medium")
            if priority == "low" and step > self.max_steps // 2:
                logger.info("Remaining modules are low priority. Stopping.")
                break

            self._execute_step(next_module, target, reasoning)
            step += 1

        # Step 3: Cross-module correlation
        logger.info("Running cross-module correlation analysis...")
        try:
            self.session.cross_correlations = self.reasoning.correlate_cross_module(
                self.completed_results
            )
        except Exception as e:
            logger.error("Correlation analysis failed: %s", e)

        # Step 4: Generate attack narrative
        logger.info("Generating attack narrative...")
        scan_result = self._build_scan_result()
        try:
            self.session.attack_narrative = self.reasoning.generate_attack_narrative(
                scan_result
            )
        except Exception as e:
            logger.error("Narrative generation failed: %s", e)

        # Step 5: Final analysis
        try:
            final_analysis = self.reasoning.analyze_findings(scan_result)
            self.session.executive_summary = final_analysis.executive_summary
        except Exception as e:
            logger.error("Final analysis failed: %s", e)

        scan_result.compute_stats()
        self.session.total_findings = scan_result.total_findings

        self.reasoning.close()
        return self.session

    def _execute_step(self, module_name: str, target: str, reasoning: str) -> None:
        """Execute a single assessment step."""
        step_num = len(self.session.steps) + 1
        logger.info(
            "Step %d: Running %s against %s (Reason: %s)",
            step_num, module_name, target, reasoning,
        )

        step = AgentStep(
            step_number=step_num,
            module_name=module_name,
            target=target,
            reasoning=reasoning,
        )

        module_class = self._available_modules[module_name]
        module = module_class(self.scan_config)

        start = time.time()
        try:
            result = module.run(target)
            result.duration_seconds = time.time() - start
            step.result = result
            step.duration_seconds = result.duration_seconds
            self.completed_results.append(result)
        except Exception as e:
            logger.error("Module %s failed: %s", module_name, e)
            step.duration_seconds = time.time() - start

        self._modules_run.add(module_name)
        self.session.steps.append(step)

    def _build_scan_result(self) -> ScanResult:
        """Build a ScanResult from completed module results."""
        result = ScanResult(engagement_id=self.scan_config.engagement_id)
        result.module_results = self.completed_results
        result.start_time = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result.compute_stats()
        return result


def run_agentic_assessment(
    scan_config: ScanConfig,
    reasoning_config: ReasoningConfig,
    targets: list[str],
    modules: dict[str, type[BaseModule]],
    max_steps: int = 20,
) -> AgentSession:
    """Convenience function to run a full agentic assessment.

    Args:
        scan_config: Scan configuration with credentials and scope
        reasoning_config: LLM provider configuration for reasoning
        targets: Initial targets to assess
        modules: Available assessment module classes
        max_steps: Maximum number of agent iterations

    Returns:
        AgentSession with all steps, correlations, and narratives
    """
    agent = PentestAgent(scan_config, reasoning_config, max_steps)
    agent.register_modules(modules)
    return agent.run(targets)
