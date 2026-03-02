"""Agentic reasoning engine for intelligent pentesting.

Uses LLM-powered analysis to make decisions during assessments:
- Analyze scan results and decide next steps
- Correlate findings across modules to identify attack chains
- Prioritize targets and attack paths
- Generate contextual exploitation strategies
- Produce executive and technical summaries
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import httpx

from iescan.core.scanner import Finding, ModuleResult, ScanResult, Severity

logger = logging.getLogger(__name__)


class ReasoningProvider(str, Enum):
    """Supported LLM providers for reasoning."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OLLAMA = "ollama"


@dataclass
class ReasoningConfig:
    """Configuration for the reasoning engine."""
    provider: ReasoningProvider = ReasoningProvider.ANTHROPIC
    model: str = "claude-sonnet-4-5-20241022"
    api_key: str = ""
    api_base: str = ""  # For Ollama or custom endpoints
    max_tokens: int = 4096
    temperature: float = 0.2  # Low temperature for analytical reasoning


@dataclass
class ReasoningResult:
    """Result from the reasoning engine."""
    analysis: str
    next_steps: list[str] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    risk_assessment: str = ""
    executive_summary: str = ""
    raw_response: str = ""


SYSTEM_PROMPT = """You are an expert penetration testing analyst specializing in internal enterprise security assessments. You analyze scan results from security assessment tools and provide:

1. **Correlation Analysis**: Connect findings across different modules (AD, network, database, etc.) to identify compound attack paths that individual tools miss.

2. **Attack Chain Mapping**: Build realistic attack chains showing how an attacker could chain multiple vulnerabilities together (e.g., Kerberoasting → password crack → lateral movement via linked SQL server → domain admin).

3. **Prioritized Next Steps**: Based on current findings, recommend which targets or attack vectors to investigate next, with reasoning.

4. **Risk Assessment**: Provide a contextual risk assessment considering the specific enterprise environment, not just generic CVSS scores.

5. **Remediation Strategy**: Prioritize fixes that break the most attack chains rather than addressing individual findings in isolation.

Always think step-by-step. Consider the attacker's perspective. Focus on findings that chain together for maximum impact. Be specific and actionable."""


class ReasoningEngine:
    """LLM-powered reasoning engine for intelligent pentesting decisions."""

    def __init__(self, config: ReasoningConfig) -> None:
        self.config = config
        self._client = httpx.Client(timeout=120.0)

    def analyze_findings(self, scan_result: ScanResult) -> ReasoningResult:
        """Analyze all scan findings and produce correlated intelligence."""
        findings_data = self._serialize_findings(scan_result)

        prompt = f"""Analyze these internal enterprise security assessment findings and provide:

1. **Attack Chain Analysis**: Identify multi-step attack paths by correlating findings across modules. Show complete chains from initial access to domain compromise.

2. **Critical Correlations**: Highlight findings that become much more dangerous when combined (e.g., Kerberoastable service account + weak password policy + linked SQL server).

3. **Next Steps**: What should be tested next based on these findings? What hasn't been covered yet?

4. **Risk Priority Matrix**: Rank the compound risks, not just individual findings.

5. **Executive Summary**: 3-4 sentence summary suitable for CISO briefing.

## Scan Results

```json
{json.dumps(findings_data, indent=2, default=str)}
```

Provide your analysis in structured JSON format with keys: attack_chains, correlations, next_steps, risk_priority, executive_summary."""

        response = self._call_llm(prompt)
        return self._parse_response(response)

    def decide_next_module(
        self,
        completed_results: list[ModuleResult],
        available_modules: list[str],
    ) -> dict[str, Any]:
        """Decide which module to run next based on current findings."""
        results_summary = []
        for r in completed_results:
            results_summary.append({
                "module": r.module_name,
                "target": r.target,
                "finding_count": len(r.findings),
                "key_findings": [
                    {"title": f.title, "severity": f.severity.value}
                    for f in r.findings
                    if f.severity in (Severity.CRITICAL, Severity.HIGH)
                ],
                "data_keys": list(r.data.keys()),
            })

        prompt = f"""Based on the assessment results so far, decide which module to run next and against which target.

## Completed Results
```json
{json.dumps(results_summary, indent=2, default=str)}
```

## Available Modules
{json.dumps(available_modules)}

Respond with JSON containing:
- "next_module": the module name to run next
- "target": the target to run it against
- "reasoning": why this is the best next step
- "expected_findings": what you expect to discover
- "priority": "critical", "high", "medium", or "low"
"""

        response = self._call_llm(prompt)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return {
                "next_module": available_modules[0] if available_modules else "none",
                "reasoning": "Fallback: running first available module",
                "raw_response": response,
            }

    def generate_attack_narrative(self, scan_result: ScanResult) -> str:
        """Generate a narrative description of the most critical attack path."""
        findings_data = self._serialize_findings(scan_result)

        prompt = f"""Based on these assessment findings, write a detailed technical narrative describing the most realistic and impactful attack path an adversary could take from initial network access to full domain compromise.

Write it as a step-by-step attack walkthrough that a senior pentester would include in a report. Include:
- Specific hosts, accounts, and services involved
- Tools and techniques at each step
- Why each step succeeds (what misconfiguration enables it)
- Detection opportunities the defenders missed

## Findings
```json
{json.dumps(findings_data, indent=2, default=str)}
```

Write in clear, professional prose suitable for a pentest report."""

        return self._call_llm(prompt)

    def correlate_cross_module(
        self, results: list[ModuleResult]
    ) -> list[dict[str, Any]]:
        """Correlate findings across different modules to find compound risks."""
        all_findings = []
        for r in results:
            for f in r.findings:
                all_findings.append({
                    "module": r.module_name,
                    "target": f.target,
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "description": f.description,
                    "evidence": f.evidence[:500],
                })

        if not all_findings:
            return []

        prompt = f"""Analyze these security findings from different assessment modules and identify CROSS-MODULE CORRELATIONS — cases where findings from different modules combine to create a more severe risk than either finding alone.

## Findings from Multiple Modules
```json
{json.dumps(all_findings, indent=2)}
```

For each correlation found, respond with a JSON array of objects containing:
- "findings_involved": list of finding titles that combine
- "compound_risk": description of the combined risk
- "compound_severity": the severity of the combined risk (critical/high/medium/low)
- "attack_scenario": how an attacker would chain these together
- "remediation_priority": which fix would break the chain most effectively

Return ONLY the JSON array."""

        response = self._call_llm(prompt)
        try:
            return json.loads(response)
        except json.JSONDecodeError:
            return []

    def _call_llm(self, prompt: str) -> str:
        """Make an LLM API call based on the configured provider."""
        if self.config.provider == ReasoningProvider.ANTHROPIC:
            return self._call_anthropic(prompt)
        elif self.config.provider == ReasoningProvider.OPENAI:
            return self._call_openai(prompt)
        elif self.config.provider == ReasoningProvider.OLLAMA:
            return self._call_ollama(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.config.provider}")

    def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic Claude API."""
        response = self._client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self.config.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": prompt}],
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["content"][0]["text"]

    def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API."""
        base = self.config.api_base or "https://api.openai.com/v1"
        response = self._client.post(
            f"{base}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"]

    def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama API."""
        base = self.config.api_base or "http://localhost:11434"
        response = self._client.post(
            f"{base}/api/generate",
            json={
                "model": self.config.model,
                "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                "stream": False,
                "options": {
                    "temperature": self.config.temperature,
                    "num_predict": self.config.max_tokens,
                },
            },
        )
        response.raise_for_status()
        data = response.json()
        return data["response"]

    def _serialize_findings(self, scan_result: ScanResult) -> dict[str, Any]:
        """Serialize scan results for LLM consumption."""
        return {
            "engagement_id": scan_result.engagement_id,
            "summary": {
                "total": scan_result.total_findings,
                "critical": scan_result.critical_count,
                "high": scan_result.high_count,
                "medium": scan_result.medium_count,
                "low": scan_result.low_count,
            },
            "modules": [
                {
                    "module": mr.module_name,
                    "target": mr.target,
                    "findings": [
                        {
                            "title": f.title,
                            "severity": f.severity.value,
                            "category": f.category.value,
                            "description": f.description,
                            "evidence": f.evidence[:500],
                            "remediation": f.remediation,
                        }
                        for f in mr.findings
                    ],
                    "data": {
                        k: v
                        for k, v in mr.data.items()
                        if not isinstance(v, (bytes, bytearray))
                    },
                }
                for mr in scan_result.module_results
            ],
        }

    def _parse_response(self, response: str) -> ReasoningResult:
        """Parse LLM response into a ReasoningResult."""
        result = ReasoningResult(analysis=response, raw_response=response)

        try:
            # Try to parse as JSON
            data = json.loads(response)
            if isinstance(data, dict):
                result.attack_chains = data.get("attack_chains", [])
                result.next_steps = data.get("next_steps", [])
                result.risk_assessment = data.get("risk_priority", "")
                result.executive_summary = data.get("executive_summary", "")
        except json.JSONDecodeError:
            # Extract sections from prose response
            result.analysis = response

        return result

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
