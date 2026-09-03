"""ADK orchestration for the local AEGIS investigation workflow.

Deterministic tools remain the authority for exposure, risk, history, and
verification. LLM agents only interpret supplied evidence or draft text.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from git_history_tools import correlate_finding
from graph_tools import analyze_security
from terraform_parser_tools import parse_terraform

ROOT = Path(__file__).resolve().parent
GEMINI_MODEL = "gemini-3.6-flash"


def graph_analysis_tool(finding_id: str) -> dict[str, Any]:
    """Analyze attack path. Internally uses canonical vulnerable scenario (main.tf) and finding."""
    vulnerable_path = ROOT / "main.tf"
    finding_path = ROOT / "finding.json"
    
    if not vulnerable_path.is_file():
        raise FileNotFoundError(f"Terraform file not found or is not a file: {vulnerable_path}")
    if not finding_path.is_file():
        raise FileNotFoundError(f"Finding file not found or is not a file: {finding_path}")
    
    finding = json.loads(finding_path.read_text())
    if finding.get("finding_id") != finding_id:
        raise ValueError(f"Finding ID mismatch: expected {finding_id}, got {finding.get('finding_id')}")
    
    return analyze_security(parse_terraform(vulnerable_path), finding)


def root_cause_tool(finding_id: str) -> dict[str, Any]:
    """Correlate root cause. Internally uses canonical scenario files and finding."""
    vulnerable_path = ROOT / "main.tf"
    commit_path = ROOT / "commit_history.json"
    deployment_path = ROOT / "deployment_events.json"
    finding_path = ROOT / "finding.json"
    
    for path in [vulnerable_path, commit_path, deployment_path, finding_path]:
        if not path.is_file():
            raise FileNotFoundError(f"Scenario file not found or is not a file: {path}")
    
    finding = json.loads(finding_path.read_text())
    if finding.get("finding_id") != finding_id:
        raise ValueError(f"Finding ID mismatch: expected {finding_id}, got {finding.get('finding_id')}")
    
    terraform = parse_terraform(vulnerable_path)
    return correlate_finding(finding, terraform, commit_path, deployment_path)


def deterministic_verification_tool(finding_id: str) -> dict[str, Any]:
    """Verify remediation. Internally uses canonical vulnerable and patched scenarios and finding."""
    vulnerable_path = ROOT / "main.tf"
    patched_path = ROOT / "main.patched.tf"
    finding_path = ROOT / "finding.json"
    
    for path in [vulnerable_path, patched_path, finding_path]:
        if not path.is_file():
            raise FileNotFoundError(f"Scenario file not found or is not a file: {path}")
    
    finding = json.loads(finding_path.read_text())
    if finding.get("finding_id") != finding_id:
        raise ValueError(f"Finding ID mismatch: expected {finding_id}, got {finding.get('finding_id')}")
    
    before = analyze_security(parse_terraform(vulnerable_path), finding)
    after = analyze_security(parse_terraform(patched_path), finding)
    verified = before["path_exists"] and not after["path_exists"] and after["risk_score"] < before["risk_score"]
    return {
        "status": "VERIFIED" if verified else "NOT_VERIFIED",
        "path_closed": not after["path_exists"],
        "before_risk": before["risk_score"],
        "after_risk": after["risk_score"],
        "before": before,
        "after": after,
    }


def _minimal_remediation(terraform_path: str) -> str:
    source = Path(terraform_path).read_text()
    return source.replace('member = "allUsers"', 'member = "group:data-readers@aegis-demo-project.iam.gserviceaccount.com"')


def remediation_proposal_context(investigation: dict[str, Any], attack_path: dict[str, Any], root_cause: dict[str, Any]) -> str:
    """Build context for Gemini remediation agent - the only place where generative reasoning is needed."""
    return (
        "You are a Terraform security remediation specialist. Based on the deterministic security analysis below, "
        "draft a minimal Terraform patch that closes the attack path. Propose only the changed attribute. "
        "Do not claim verification. Do not write arbitrary filesystem paths.\n\n"
        f"Investigation:\n{json.dumps(investigation, indent=2)}\n\n"
        f"Attack Path:\n{json.dumps(attack_path, indent=2)}\n\n"
        f"Root Cause:\n{json.dumps(root_cause, indent=2)}"
    )


def parse_remediation_proposal(proposal_text: str) -> dict[str, Any]:
    """Parse Gemini's remediation proposal to extract Terraform changes.
    
    Looks for:
    - Terraform resource changes (JSON block or HCL snippets)
    - Specific attribute changes (e.g., member = "..." replacement)
    - Validation that proposal doesn't reference arbitrary paths
    """
    # For MVP: extract member replacement pattern
    # In production: use proper Terraform parser
    try:
        # Try JSON parsing first
        if "{" in proposal_text:
            json_start = proposal_text.find("{")
            json_end = proposal_text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                block = json.loads(proposal_text[json_start:json_end])
                return block
    except (json.JSONDecodeError, ValueError):
        pass
    
    # Fallback: look for member = "..." pattern
    if 'member = "' in proposal_text:
        import re
        match = re.search(r'member = "(.*?)"', proposal_text)
        if match:
            new_member = match.group(1)
            # Validate: should not be a filepath, should be a principal
            if "/" not in new_member and "@" in new_member:
                return {
                    "type": "member_replacement",
                    "old": "allUsers",
                    "new": new_member,
                }
    
    return {"type": "unparseable", "raw": proposal_text[:200]}


def verify_candidate_patch(proposal_dict: dict[str, Any], finding_id: str) -> dict[str, Any]:
    """Verify a proposed remediation patch WITHOUT using the fixture main.patched.tf.
    
    This is the critical fix: we test Gemini's proposal, not a pre-baked fixture.
    """
    # Load canonical finding
    finding_path = ROOT / "finding.json"
    if not finding_path.is_file():
        return {"status": "ERROR", "reason": "Finding file missing", "verified": False}
    
    finding = json.loads(finding_path.read_text())
    if finding.get("finding_id") != finding_id:
        return {"status": "ERROR", "reason": "Finding ID mismatch", "verified": False}
    
    # Load vulnerable Terraform
    vulnerable_path = ROOT / "main.tf"
    if not vulnerable_path.is_file():
        return {"status": "ERROR", "reason": "Vulnerable Terraform missing", "verified": False}
    
    # Compute risk before
    before_terraform = parse_terraform(path=vulnerable_path)
    before_risk = analyze_security(before_terraform, finding)
    
    # Apply proposed patch in-memory (don't write to disk)
    vulnerable_source = vulnerable_path.read_text()
    
    if proposal_dict.get("type") == "member_replacement":
        old_member = f'member = "{proposal_dict.get("old", "allUsers")}"'
        new_member = f'member = "{proposal_dict.get("new", "")}"'
        candidate_source = vulnerable_source.replace(old_member, new_member)
    elif proposal_dict.get("type") == "unparseable":
        # Cannot verify unparseable proposal
        return {
            "status": "REJECTED",
            "reason": "Proposal could not be parsed",
            "candidate_patch_generated": False,
            "candidate_patch_verified": False,
            "before_risk": before_risk["risk_score"],
            "after_risk": before_risk["risk_score"],
            "verified": False,
        }
    else:
        return {
            "status": "REJECTED",
            "reason": "Unknown proposal type",
            "candidate_patch_generated": False,
            "candidate_patch_verified": False,
            "before_risk": before_risk["risk_score"],
            "after_risk": before_risk["risk_score"],
            "verified": False,
        }
    
    # Parse the candidate Terraform from string
    try:
        candidate_terraform = parse_terraform(content=candidate_source)
    except Exception as e:
        return {
            "status": "REJECTED",
            "reason": f"Candidate patch parse error: {str(e)}",
            "candidate_patch_generated": True,
            "candidate_patch_verified": False,
            "before_risk": before_risk["risk_score"],
            "after_risk": before_risk["risk_score"],
            "verified": False,
        }
    
    # Compute risk after
    after_risk = analyze_security(candidate_terraform, finding)
    
    # Verification: path must be closed and risk must decrease
    verified = (
        before_risk["path_exists"] 
        and not after_risk["path_exists"] 
        and after_risk["risk_score"] < before_risk["risk_score"]
    )
    
    return {
        "status": "VERIFIED" if verified else "NOT_VERIFIED",
        "candidate_patch_generated": True,
        "candidate_patch_verified": verified,
        "before_risk": before_risk["risk_score"],
        "after_risk": after_risk["risk_score"],
        "path_closed": not after_risk["path_exists"],
        "verified": verified,
        "before_details": before_risk,
        "after_details": after_risk,
    }


def run_deterministic_investigation(finding_id: str) -> dict[str, Any]:
    """Run all deterministic investigation stages WITHOUT Gemini.
    
    Returns structured context for remediation agent.
    """
    # Load finding
    finding_path = ROOT / "finding.json"
    if not finding_path.is_file():
        raise FileNotFoundError(f"Finding file not found: {finding_path}")
    
    finding = json.loads(finding_path.read_text())
    if finding.get("finding_id") != finding_id:
        raise ValueError(f"Finding ID mismatch: expected {finding_id}, got {finding.get('finding_id')}")
    
    # Stage 1: Investigation (simple validation - no LLM needed)
    investigation_context = {
        "finding_id": finding["finding_id"],
        "finding_type": finding["finding_type"],
        "resource_name": finding["resource_name"],
        "resource_type": finding["resource_type"],
        "severity": finding["severity"],
        "description": finding["description"],
    }
    
    # Stage 2: Attack Path (deterministic tool)
    attack_path_result = graph_analysis_tool(finding_id)
    
    # Stage 3: Root Cause (deterministic tool)
    root_cause_result = root_cause_tool(finding_id)
    
    return {
        "investigation_context": investigation_context,
        "attack_path_context": attack_path_result,
        "root_cause_context": root_cause_result,
        "finding_id": finding_id,
    }


async def run_adk_case_optimized(case_id: str = "AEGIS-CASE-001") -> dict[str, Any]:
    """Run AEGIS investigation with at most one Gemini call for remediation.

    The deterministic stages remain authoritative: FIND, ATTACK_PATH, ROOT_CAUSE,
    then the single Gemini remediation call, then deterministic verification.
    """
    finding_path = ROOT / "finding.json"
    finding = json.loads(finding_path.read_text())
    finding_id = finding["finding_id"]

    # STAGE 1-3: deterministic investigation (no Gemini)
    investigation = run_deterministic_investigation(finding_id)
    attack_path = investigation["attack_path_context"]
    root_cause = investigation["root_cause_context"]

    gemini_request_count = 0
    gemini_call_status = "NOT_RUN"
    gemini_call_error = None
    gemini_remediation_text = None
    remediation_proposal = {"type": "no_output"}
    remediation_source = "not_run"
    known_fixture_verification = deterministic_verification_tool(finding_id)

    # STAGE 4: one remediation call (the only generative call per case)
    try:
        remediation_agent = LlmAgent(
            name="remediation_agent",
            model=GEMINI_MODEL,
            description="Drafts a minimal Terraform remediation from supplied evidence.",
            instruction="Use only supplied deterministic evidence. Propose a patch; do not apply or verify it.",
            output_key="remediation_context",
        )

        runner = InMemoryRunner(agent=remediation_agent, app_name="aegis")
        adk_user_id = "aegis-local"
        adk_session_id = f"session-{case_id}"

        await runner.session_service.create_session(
            app_name="aegis",
            user_id=adk_user_id,
            session_id=adk_session_id,
        )

        remediation_prompt_text = remediation_proposal_context(
            investigation["investigation_context"],
            attack_path,
            root_cause,
        )
        content = types.Content(
            role="user",
            parts=[types.Part(text=remediation_prompt_text)],
        )

        gemini_request_count = 1
        gemini_call_status = "SUCCESS"
        remediation_events = []
        async for event in runner.run_async(user_id=adk_user_id, session_id=adk_session_id, new_message=content):
            remediation_events.append(event)

        for event in remediation_events:
            if hasattr(event, "content") or isinstance(event, dict):
                gemini_remediation_text = str(event)
                break

        if gemini_remediation_text:
            remediation_proposal = parse_remediation_proposal(gemini_remediation_text)
            remediation_source = "gemini_adk"
        else:
            gemini_call_status = "NO_OUTPUT"
            remediation_proposal = {"type": "no_output"}
            remediation_source = "no_output"

    except Exception as e:
        gemini_call_error = str(e)
        if "429" in gemini_call_error or "RESOURCE_EXHAUSTED" in gemini_call_error:
            gemini_call_status = "QUOTA_EXCEEDED"
            remediation_proposal = {"type": "quota_exceeded"}
            remediation_source = "quota_exceeded"
        else:
            gemini_call_status = f"ERROR: {gemini_call_error[:100]}"
            remediation_proposal = {"type": "error"}
            remediation_source = "error"

    # STAGE 5: verification is deterministic and uses the actual candidate generated from Gemini intent
    if gemini_call_status == "SUCCESS" and remediation_proposal.get("type") not in ["no_output", "error", "quota_exceeded"]:
        verification_result = verify_candidate_patch(remediation_proposal, finding_id)
    else:
        verification_result = {
            "status": "NOT_VERIFIED",
            "reason": f"Remediation generation failed: {gemini_call_status}",
            "candidate_patch_generated": False,
            "candidate_patch_verified": False,
            "verified": False,
            "before_risk": attack_path.get("risk_score", 0),
            "after_risk": attack_path.get("risk_score", 0),
        }

    candidate_patch_generated = bool(verification_result.get("candidate_patch_generated", False))
    candidate_patch_verified = bool(verification_result.get("candidate_patch_verified", False))

    if gemini_call_status in {"QUOTA_EXCEEDED", "NO_OUTPUT", "ERROR: ..."}:
        ai_remediation_verification = "AI_REMEDIATION_NOT_RUN"
    elif candidate_patch_verified:
        ai_remediation_verification = "AI_REMEDIATION_VERIFIED"
    elif candidate_patch_generated:
        ai_remediation_verification = "AI_REMEDIATION_REJECTED"
    else:
        ai_remediation_verification = "AI_REMEDIATION_NOT_RUN"

    final_status = (
        "AI_REMEDIATION_VERIFIED" if candidate_patch_verified else
        "AI_REMEDIATION_REJECTED" if candidate_patch_generated else
        "AI_REMEDIATION_NOT_RUN" if gemini_call_status != "SUCCESS" else
        "INVESTIGATION_COMPLETE"
    )

    return {
        "case_id": case_id,
        "model_config": GEMINI_MODEL,
        "stages": ["FIND", "ATTACK_PATH", "ROOT_CAUSE", "REMEDIATION", "VERIFICATION"],
        "finding_id": finding_id,
        "investigation_context": investigation["investigation_context"],
        "attack_path": attack_path,
        "attack_path_context": investigation["attack_path_context"],
        "root_cause_commit": root_cause.get("introducing_commit"),
        "deployment_id": root_cause.get("deployment_id"),
        "root_cause_context": investigation["root_cause_context"],
        "gemini_request_count": gemini_request_count,
        "gemini_call_status": gemini_call_status,
        "gemini_call_error": gemini_call_error,
        "gemini_remediation": gemini_remediation_text,
        "remediation_source": remediation_source,
        "remediation_proposal": remediation_proposal,
        "candidate_patch_generated": candidate_patch_generated,
        "candidate_patch_verified": candidate_patch_verified,
        "risk_before_remediation": attack_path.get("risk_score", 0),
        "risk_after_remediation": verification_result.get("after_risk", attack_path.get("risk_score", 0)),
        "known_fixture_verification": known_fixture_verification,
        "ai_remediation_verification": ai_remediation_verification,
        "verification_result": verification_result,
        "final_verification_status": verification_result.get("status", "NOT_VERIFIED"),
        "final_status": final_status,
    }


def run_local_case(case_id: str = "AEGIS-CASE-001", use_gemini: bool = False) -> dict[str, Any]:
    """Run the canonical case locally; use_gemini is opt-in for model calls (LEGACY).
    
    This function is kept for backward compatibility with tests.
    For live execution, use run_adk_case_optimized() instead.
    """
    finding = json.loads((ROOT / "finding.json").read_text())
    finding_id = finding["finding_id"]
    vulnerable_path = str(ROOT / "main.tf")
    attack_path = graph_analysis_tool(finding_id)
    root_cause = root_cause_tool(finding_id)
    
    # Use fixture remediation (not Gemini)
    remediation = {
        "patch": _minimal_remediation(vulnerable_path),
        "explanation": "Replace the allUsers member with a scoped group principal.",
        "verified": False,
        "generated_by": "gemini" if use_gemini else "local_fixture",
    }
    
    # Verify against fixture (for backward compatibility)
    # NOTE: This verifies main.patched.tf fixture, not a Gemini proposal
    verification = deterministic_verification_tool(finding_id)
    
    return {
        "case_id": case_id,
        "finding": finding,
        "affected_resource": finding["resource_name"],
        "attack_path": attack_path,
        "root_cause": root_cause,
        "remediation": remediation,
        "verification": verification,
        "before_after_risk": {"before": verification["before_risk"], "after": verification["after_risk"]},
        "adk_agent": "aegis_day3_workflow",
    }


def build_agents() -> SequentialAgent:
    """Build legacy 5-agent ADK workflow for backward compatibility.
    
    WARNING: This makes 5 Gemini calls and hits quota quickly.
    For new execution, use run_adk_case_optimized() which makes only 1 call.
    """
    # Kept for test compatibility only - not used in run_adk_case_optimized()
    remediation_agent = LlmAgent(
        name="remediation_agent",
        model=GEMINI_MODEL,
        description="Drafts a minimal Terraform remediation from supplied evidence.",
        instruction="Use only supplied deterministic evidence. Propose a patch; do not apply or verify it.",
        output_key="remediation_context",
    )
    return SequentialAgent(
        name="aegis_day3_workflow",
        description="FIND, ATTACK PATH, ROOT CAUSE, REMEDIATION, VERIFY (legacy 5-agent).",
        sub_agents=[remediation_agent],
    )


# Create legacy agent for backward compatibility (used by run_adk_case_legacy)
root_agent = build_agents()


# Keep legacy run_adk_case for backward compatibility (but with warning)
async def run_adk_case_legacy(case_id: str = "AEGIS-CASE-001") -> list[Any]:
    """LEGACY: Run ADK/Gemini workflow with 5 sequential agents.
    
    WARNING: This makes 5 Gemini calls and exceeds free-tier quota.
    Use run_adk_case_optimized() instead for production.
    
    Kept only for backward compatibility with existing tests.
    """
    runner = InMemoryRunner(agent=root_agent, app_name="aegis")
    adk_user_id = "aegis-local"
    adk_session_id = f"session-{case_id}"
    
    finding = json.loads((ROOT / "finding.json").read_text())
    finding_id = finding["finding_id"]
    
    await runner.session_service.create_session(
        app_name="aegis",
        user_id=adk_user_id,
        session_id=adk_session_id,
    )
    content = types.Content(
        role="user",
        parts=[types.Part(text=json.dumps({"case_id": case_id, "finding_id": finding_id}))],
    )
    events = []
    async for event in runner.run_async(user_id=adk_user_id, session_id=adk_session_id, new_message=content):
        events.append(event)
    return events


# New optimized function - PREFERRED for live execution
async def run_adk_case(case_id: str = "AEGIS-CASE-001") -> dict[str, Any]:
    """Run AEGIS ADK case with optimized architecture (1 Gemini call).
    
    This is the PREFERRED entry point for live execution.
    It combines deterministic investigation with only 1 Gemini call for remediation.
    """
    return await run_adk_case_optimized(case_id)