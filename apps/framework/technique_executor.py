"""
Unified technique executor — runs LIVE LLM attacks, SIMULATED telemetry, and hybrid chains.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

import requests

from framework.chain_engine import KILL_CHAIN_MAP, create_engine
from framework.technique_playbooks import (
    TechniquePlaybook,
    get_all_playbooks,
    get_coverage_matrix,
    get_playbook,
)
from framework.taxonomy import TECHNIQUE_REGISTRY, get_technique

logger = logging.getLogger("acme.technique_executor")


class TechniqueExecutor:
    def __init__(
        self,
        banking_url: str,
        otel_endpoint: str,
        service_name: str = "acme-banking-fabric",
    ):
        self.banking_url = banking_url.rstrip("/")
        self.otel_endpoint = otel_endpoint
        self.engine = create_engine(otel_endpoint, service_name)

    def execute_technique(
        self,
        technique_id: str,
        incident_id: Optional[str] = None,
        force_mode: Optional[str] = None,
    ) -> dict:
        playbook = get_playbook(technique_id)
        if not playbook:
            return {"error": f"Unknown technique: {technique_id}", "success": False}

        technique = get_technique(technique_id)
        mode = force_mode or playbook.execution_mode
        incident_id = incident_id or f"ACME-INC-{uuid.uuid4().hex[:8].upper()}"

        result: Dict[str, Any] = {
            "technique_id": technique_id,
            "technique_name": playbook.technique_name,
            "execution_mode": mode,
            "incident_id": incident_id,
            "target_agent": playbook.target_agent,
            "is_top_10": playbook.is_top_10,
            "threat_hunt_spl": playbook.threat_hunt_spl,
            "rogue_actor_story": playbook.rogue_actor_story,
            "success": True,
        }

        if mode in ("LIVE", "HYBRID"):
            if technique_id == "AML.T0072":
                result["live"] = self._run_memory_drift_live(playbook, incident_id)
            else:
                result["live"] = self._run_live(playbook, incident_id)

        if mode in ("SIMULATED", "HYBRID"):
            result["simulated"] = self._run_simulated(playbook, technique, incident_id)

        return result

    def execute_all(
        self,
        delay_seconds: float = 0.3,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
    ) -> dict:
        playbooks = get_all_playbooks()
        total = len(playbooks)
        results: List[dict] = []
        campaign_id = f"ACME-CAMP-{uuid.uuid4().hex[:8].upper()}"

        for index, playbook in enumerate(playbooks, start=1):
            outcome = self.execute_technique(
                playbook.technique_id,
                incident_id=f"{campaign_id}-T{index:02d}",
            )
            results.append(outcome)
            if on_progress:
                on_progress(index, total, playbook.technique_id)
            if index < total and delay_seconds > 0:
                time.sleep(delay_seconds)

        live_ok = sum(1 for r in results if r.get("live", {}).get("success"))
        sim_ok = sum(1 for r in results if r.get("simulated", {}).get("emitted"))

        return {
            "campaign_id": campaign_id,
            "total_techniques": total,
            "live_executions": live_ok,
            "simulated_emissions": sim_ok,
            "coverage": get_coverage_matrix(),
            "results": results,
        }

    def execute_chain(
        self,
        chain_id: str,
        accelerated: bool = True,
        hybrid_live: bool = True,
    ) -> dict:
        chain = KILL_CHAIN_MAP.get(chain_id)
        if not chain:
            raise ValueError(f"Unknown chain_id: {chain_id}")

        def _stage_callback(stage_num: int, technique_id: str, _success: bool) -> None:
            if not hybrid_live:
                return
            playbook = get_playbook(technique_id)
            if playbook and playbook.execution_mode in ("LIVE", "HYBRID"):
                self._run_live(playbook, incident_holder["id"])

        incident_holder = {"id": f"ACME-INC-{uuid.uuid4().hex[:8].upper()}"}

        report = self.engine.execute_chain(
            chain_id,
            accelerated=accelerated,
            on_stage_complete=_stage_callback,
            incident_id=incident_holder["id"],
            enrich_playbooks=True,
        )
        report["hybrid_live_stages"] = hybrid_live
        report["threat_actor_narrative"] = self._chain_narrative(chain_id, report)
        return report

    def _run_live(
        self,
        playbook: TechniquePlaybook,
        incident_id: str,
        session_id: Optional[str] = None,
    ) -> dict:
        path = f"/api/v1/agent/{playbook.target_agent}"
        payload = {
            "message": playbook.payload,
            "incident_id": incident_id,
            "technique_id": playbook.technique_id,
            "testbed_mode": "TECHNIQUE_LAB_LIVE",
            "session_id": session_id or f"TECH-{playbook.technique_id}-{uuid.uuid4().hex[:6].upper()}",
            "campaign_week": playbook.scenario_week or 0,
        }
        try:
            response = requests.post(
                f"{self.banking_url}{path}",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=180,
            )
            body = response.json() if response.content else {}
            blocked = bool(
                body.get("acme_output_guard_blocked")
                or body.get("acme_input_guard_blocked")
                or body.get("workflow_blocked")
                or body.get("blocked")
            )
            return {
                "success": response.status_code < 500,
                "http_status": response.status_code,
                "blocked": blocked,
                "status": "BLOCKED" if blocked else "INJECTED",
                "agent_id": playbook.target_agent,
                "preview": str(body.get("response", body.get("final_output", "")))[:200],
                "body": body,
            }
        except requests.RequestException as exc:
            logger.error("Live technique execution failed: %s", exc)
            return {"success": False, "error": str(exc)}

    def _run_memory_drift_live(self, playbook: TechniquePlaybook, incident_id: str) -> dict:
        """Multi-turn LIVE execution for AML.T0072 memory behavioral drift."""
        from framework.emerging_threats import MEMORY_DRIFT_TURNS

        session_id = f"MEM-DRIFT-{uuid.uuid4().hex[:8].upper()}"
        agents = [
            "acme-agent-intake-001",
            "acme-agent-docingest-002",
            "acme-agent-creditrisk-003",
            "acme-agent-creditrisk-003",
            "acme-agent-compliance-004",
        ]
        turns: List[dict] = []
        for index, (turn_text, agent_id) in enumerate(zip(MEMORY_DRIFT_TURNS, agents), start=1):
            path = f"/api/v1/agent/{agent_id}"
            payload = {
                "message": turn_text,
                "incident_id": incident_id,
                "technique_id": playbook.technique_id,
                "testbed_mode": "TECHNIQUE_LAB_LIVE",
                "session_id": session_id,
                "campaign_week": 0,
            }
            try:
                response = requests.post(
                    f"{self.banking_url}{path}",
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=180,
                )
                body = response.json() if response.content else {}
                turns.append({
                    "turn": index,
                    "agent_id": agent_id,
                    "http_status": response.status_code,
                    "memory_entry_trust_score": body.get("memory_entry_trust_score"),
                    "approval_rate_by_session": body.get("approval_rate_by_session"),
                    "memory_drift_detected": body.get("memory.drift_detected"),
                })
            except requests.RequestException as exc:
                turns.append({"turn": index, "agent_id": agent_id, "error": str(exc)})

        return {
            "success": True,
            "multi_turn": True,
            "session_id": session_id,
            "turns": turns,
            "turn_count": len(turns),
        }

    def _run_simulated(
        self,
        playbook: TechniquePlaybook,
        technique,
        incident_id: str,
    ) -> dict:
        extra = {
            "incident_id": incident_id,
            "testbed_mode": "TECHNIQUE_LAB_SIMULATED",
            "execution_mode": playbook.execution_mode,
            "practitioner_narrative": playbook.practitioner_narrative,
            "rogue_actor_story": playbook.rogue_actor_story,
            "risk_statement": playbook.risk_statement,
            "threat_hunt_spl": playbook.threat_hunt_spl,
            "threat_hunt_steps": " | ".join(playbook.threat_hunt_steps),
            "technique_id": playbook.technique_id,
            "is_top_10": str(playbook.is_top_10).lower(),
        }
        from framework.emerging_threats import enrich_simulated_emission

        extra.update(enrich_simulated_emission(playbook.technique_id, incident_id))
        extra["technique_id"] = playbook.technique_id
        emitted = self.engine.emit_single_technique(
            playbook.technique_id,
            playbook.target_agent,
            extra_fields=extra,
        )
        return {"emitted": emitted, "agent_id": playbook.target_agent}

    def _chain_narrative(self, chain_id: str, report: dict) -> List[dict]:
        narrative: List[dict] = []
        chain = KILL_CHAIN_MAP[chain_id]
        for stage_result in report.get("stage_results", []):
            playbook = get_playbook(stage_result["technique_id"])
            narrative.append({
                "stage": stage_result["stage_num"],
                "stage_name": stage_result["stage_name"],
                "technique_id": stage_result["technique_id"],
                "severity": stage_result["severity"],
                "story": playbook.rogue_actor_story if playbook else "",
                "hunt_spl": playbook.threat_hunt_spl if playbook else "",
                "risk": playbook.risk_statement if playbook else "",
            })
        narrative.insert(0, {
            "chain_id": chain_id,
            "chain_name": chain.name,
            "threat_actor": chain.threat_actor_profile,
            "analogy": chain.real_world_analogy,
            "summary": chain.description,
        })
        return narrative


def create_executor(
    banking_url: Optional[str] = None,
    otel_endpoint: Optional[str] = None,
) -> TechniqueExecutor:
    import os

    return TechniqueExecutor(
        banking_url=banking_url or os.environ.get("BANKING_APP_URL", "http://banking_app:5000"),
        otel_endpoint=otel_endpoint or os.environ.get("OTEL_COLLECTOR_HTTP", "http://otel_collector:4318"),
    )
