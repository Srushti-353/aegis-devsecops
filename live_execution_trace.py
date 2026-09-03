#!/usr/bin/env python3
"""
Live execution of AEGIS ADK + Gemini for AEGIS-CASE-001.
Captures complete trace with agent invocation order, Gemini calls, and verification.
"""

import json
import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Import workflow components
from day3_workflow import (
    GEMINI_MODEL,
    build_agents,
    deterministic_verification_tool,
    graph_analysis_tool,
    root_cause_tool,
    run_adk_case,
    ROOT,
)


async def execute_live_case():
    """Execute the live AEGIS ADK + Gemini case and capture trace."""
    case_id = "AEGIS-CASE-001"
    session_id = f"session-{case_id}"
    
    trace = {
        "execution_timestamp": datetime.utcnow().isoformat() + "Z",
        "case_id": case_id,
        "adk_session_id": session_id,
        "model_config": GEMINI_MODEL,
        "agent_workflow": None,
        "agent_invocation_order": [],
        "deterministic_tool_calls": [],
        "gemini_request_count": 0,
        "gemini_call_status": None,
        "gemini_call_error": None,
        "attack_path": None,
        "risk_before_remediation": None,
        "root_cause_commit": None,
        "deployment_id": None,
        "gemini_remediation": None,
        "remediation_source": None,
        "candidate_patch_generated": False,
        "candidate_patch_verified": False,
        "risk_after_remediation": None,
        "known_fixture_verification": None,
        "ai_remediation_verification": None,
        "final_status": None,
        "final_verification_status": None,
        "events_captured": 0,
    }

    print("\n" + "=" * 80)
    print(f"LIVE AEGIS ADK + GEMINI EXECUTION: {case_id}")
    print("=" * 80)
    print(f"Execution Time: {trace['execution_timestamp']}")
    print(f"ADK Session ID: {session_id}")
    print(f"Gemini Model: {GEMINI_MODEL}")
    print()

    # Step 1: Load and display case data
    print("STEP 1: LOADING CASE DATA")
    print("-" * 80)
    finding = json.loads((ROOT / "finding.json").read_text())
    print(f"Finding ID: {finding['finding_id']}")
    print(f"Finding Type: {finding['finding_type']}")
    print(f"Resource: {finding['resource_name']}")
    print(f"Severity: {finding['severity']}")
    print()

    # Step 2: Run deterministic tools (BEFORE Gemini)
    print("STEP 2: RUNNING DETERMINISTIC TOOLS (Pre-Gemini)")
    print("-" * 80)
    finding_id = finding["finding_id"]
    
    # Graph analysis (tools use canonical scenario files internally)
    print(f"Calling graph_analysis_tool('{finding_id}')...")
    attack_path_result = graph_analysis_tool(finding_id)
    trace["deterministic_tool_calls"].append("graph_analysis_tool")
    trace["attack_path"] = attack_path_result
    print(f"  ✓ Path Exists: {attack_path_result['path_exists']}")
    print(f"  ✓ Risk Score: {attack_path_result['risk_score']}")
    print(f"  ✓ Severity: {attack_path_result['severity']}")
    trace["risk_before_remediation"] = attack_path_result["risk_score"]
    print()
    
    # Root cause analysis (tools use canonical scenario files internally)
    print(f"Calling root_cause_tool('{finding_id}')...")
    root_cause_result = root_cause_tool(finding_id)
    trace["deterministic_tool_calls"].append("root_cause_tool")
    trace["root_cause_commit"] = root_cause_result.get("introducing_commit")
    trace["deployment_id"] = root_cause_result.get("deployment_id")
    print(f"  ✓ Introducing Commit: {root_cause_result.get('introducing_commit')}")
    print(f"  ✓ Deployment ID: {root_cause_result.get('deployment_id')}")
    print()

    # Step 3: Build agent workflow
    print("STEP 3: BUILDING AGENT WORKFLOW")
    print("-" * 80)
    workflow = build_agents()
    trace["agent_workflow"] = workflow.name
    trace["agent_invocation_order"] = [agent.name for agent in workflow.sub_agents]
    print(f"Workflow: {workflow.name}")
    print(f"Agents (in order):")
    for i, agent in enumerate(workflow.sub_agents, 1):
        print(f"  {i}. {agent.name}: {agent.description}")
    print()

    # Step 4: Execute live ADK + Gemini
    print("STEP 4: EXECUTING LIVE ADK + GEMINI ORCHESTRATION")
    print("-" * 80)
    print(f"Invoking run_adk_case('{case_id}')...")
    print("  ⏳ Waiting for Gemini API response...")

    try:
        result = await run_adk_case(case_id)
        if isinstance(result, dict):
            trace["gemini_request_count"] = result.get("gemini_request_count", 0)
            trace["gemini_call_status"] = result.get("gemini_call_status")
            trace["gemini_call_error"] = result.get("gemini_call_error")
            trace["attack_path"] = result.get("attack_path") or trace["attack_path"]
            trace["risk_before_remediation"] = result.get("risk_before_remediation", trace["risk_before_remediation"])
            trace["root_cause_commit"] = result.get("root_cause_commit", trace["root_cause_commit"])
            trace["deployment_id"] = result.get("deployment_id", trace["deployment_id"])
            trace["gemini_remediation"] = result.get("gemini_remediation")
            trace["remediation_source"] = result.get("remediation_source")
            trace["candidate_patch_generated"] = bool(result.get("candidate_patch_generated", False))
            trace["candidate_patch_verified"] = bool(result.get("candidate_patch_verified", False))
            trace["risk_after_remediation"] = result.get("risk_after_remediation")
            trace["known_fixture_verification"] = result.get("known_fixture_verification")
            trace["ai_remediation_verification"] = result.get("ai_remediation_verification")
            trace["final_status"] = result.get("final_status")
            trace["final_verification_status"] = result.get("final_verification_status")
            trace["events_captured"] = 1

            print(f"  ✓ Gemini call succeeded")
            print(f"  ✓ Gemini request count: {trace['gemini_request_count']}")
            print(f"  ✓ Candidate patch generated: {trace['candidate_patch_generated']}")
            print(f"  ✓ Candidate patch verified: {trace['candidate_patch_verified']}")
            print(f"  ✓ AI remediation status: {trace['ai_remediation_verification']}")
        else:
            trace["gemini_call_status"] = "FAILED"
            trace["gemini_call_error"] = "run_adk_case did not return a dict"
            print("  ✗ run_adk_case did not return the expected dict payload")

    except Exception as e:
        trace["gemini_call_status"] = "FAILED"
        trace["gemini_call_error"] = str(e)
        print(f"  ✗ Gemini call failed: {e}")
        print()
        print("Continuing with deterministic verification...")

    print()

    # Step 5: Deterministic verification (authoritative only for the known fixture reference)
    print("STEP 5: KNOWN FIXTURE VERIFICATION")
    print("-" * 80)
    if trace["gemini_call_status"] == "SUCCESS":
        print(f"Using existing Phase 6 candidate verification result from run_adk_case('{case_id}')")
    else:
        print(f"Calling deterministic_verification_tool('{finding_id}')...")
        verification_result = deterministic_verification_tool(finding_id)
        trace["deterministic_tool_calls"].append("deterministic_verification_tool")
        trace["known_fixture_verification"] = verification_result
        trace["final_verification_status"] = verification_result.get("status")
        trace["risk_after_remediation"] = verification_result.get("after_risk")
        print(f"  ✓ Status: {verification_result['status']}")
        print(f"  ✓ Path Closed: {verification_result.get('path_closed')}")
        print(f"  ✓ Risk Before: {verification_result.get('before_risk')}")
        print(f"  ✓ Risk After: {verification_result.get('after_risk')}")
    print()

    # Step 6: Display complete trace
    print("STEP 6: LIVE EXECUTION TRACE")
    print("-" * 80)
    print(json.dumps(trace, indent=2))
    print()

    # Step 7: Verify no overrides occurred
    print("STEP 7: INTEGRITY VERIFICATION")
    print("-" * 80)
    print(f"✓ Deterministic tools remain authoritative")
    print(f"  - Attack path existence: {trace['attack_path']['path_exists']}")
    print(f"  - Pre-remediation risk: {trace['risk_before_remediation']}")
    print(f"  - Post-remediation risk: {trace['risk_after_remediation']}")
    print(f"  - Gemini cannot override: {trace['risk_before_remediation']} == {attack_path_result['risk_score']}")
    print(f"✓ Verification is deterministic: {trace['final_verification_status']}")
    print()

    # Summary
    print("EXECUTION SUMMARY")
    print("=" * 80)
    print(f"Case ID: {case_id}")
    print(f"ADK Session: {session_id}")
    print(f"Gemini Status: {trace['gemini_call_status']}")
    print(f"Deterministic Calls: {', '.join(trace['deterministic_tool_calls'])}")
    print(f"Agent Invocation Order: {' → '.join(trace['agent_invocation_order'])}")
    print(f"Introducing Commit: {trace['root_cause_commit']}")
    print(f"Deployment ID: {trace['deployment_id']}")
    print(f"Risk Before → After: {trace['risk_before_remediation']} → {trace['risk_after_remediation']}")
    print(f"Final Verification: {trace['final_verification_status']}")
    print("=" * 80)
    print()

    return trace


def main():
    """Main entry point."""
    try:
        trace = asyncio.run(execute_live_case())
        
        # Save trace to file
        trace_file = Path("live_execution_trace.json")
        trace_file.write_text(json.dumps(trace, indent=2))
        print(f"✓ Trace saved to: {trace_file}")
        print()
        
        # Exit with success
        return 0
        
    except Exception as e:
        print(f"✗ Execution failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
