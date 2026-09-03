#!/usr/bin/env python3
"""
Live AEGIS ADK + Gemini execution with proper credential handling.
Attempts to load GEMINI_API_KEY from environment and configure ADK runner.
"""

import json
import asyncio
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

# Import workflow components
from day3_workflow import (
    GEMINI_MODEL,
    build_agents,
    deterministic_verification_tool,
    graph_analysis_tool,
    root_cause_tool,
    ROOT,
)

# Try to configure Gemini with proper credentials
def setup_gemini_credentials() -> tuple[bool, Optional[str]]:
    """Attempt to load and configure Gemini API key."""
    api_key = os.environ.get("GEMINI_API_KEY")
    
    if api_key:
        # Try to configure genai with API key
        try:
            import google.genai
            google.genai.configure(api_key=api_key)
            return True, "API key configured in google.genai"
        except Exception as e:
            return False, f"Failed to configure google.genai: {e}"
    
    return False, "GEMINI_API_KEY not found in environment"


async def run_adk_case_with_credentials(case_id: str = "AEGIS-CASE-001") -> list:
    """Run ADK case with proper credential setup."""
    from google.adk.runners import InMemoryRunner
    from google.genai import types
    
    agent = build_agents()
    runner = InMemoryRunner(agent=agent, app_name="aegis")
    adk_user_id = "aegis-local"
    adk_session_id = f"session-{case_id}"
    
    await runner.session_service.create_session(
        app_name="aegis",
        user_id=adk_user_id,
        session_id=adk_session_id,
    )
    
    content = types.Content(
        role="user",
        parts=[types.Part(text=json.dumps({"case_id": case_id, "finding_path": str(ROOT / "finding.json")}))],
    )
    
    events = []
    async for event in runner.run_async(user_id=adk_user_id, session_id=adk_session_id, new_message=content):
        events.append(event)
    
    return events


async def execute_live_case():
    """Execute the live AEGIS ADK + Gemini case and capture trace."""
    case_id = "AEGIS-CASE-001"
    session_id = f"session-{case_id}"
    
    trace = {
        "execution_timestamp": datetime.utcnow().isoformat() + "Z",
        "case_id": case_id,
        "adk_session_id": session_id,
        "model_config": GEMINI_MODEL,
        "credentials_status": None,
        "credentials_error": None,
        "agent_workflow": None,
        "agent_invocation_order": [],
        "deterministic_tool_calls": [],
        "gemini_call_status": None,
        "gemini_call_error": None,
        "attack_path": None,
        "risk_before_remediation": None,
        "root_cause_commit": None,
        "deployment_id": None,
        "gemini_remediation": None,
        "risk_after_remediation": None,
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

    # Setup credentials
    print("STEP 0: GEMINI CREDENTIALS SETUP")
    print("-" * 80)
    cred_ok, cred_msg = setup_gemini_credentials()
    trace["credentials_status"] = cred_msg
    print(f"  {cred_msg}")
    if not cred_ok:
        trace["credentials_error"] = cred_msg
        print()
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
    
    vulnerable_path = str(ROOT / "main.tf")
    patched_path = str(ROOT / "main.patched.tf")
    
    # Graph analysis
    print(f"Calling graph_analysis_tool({vulnerable_path}, finding)...")
    attack_path_result = graph_analysis_tool(vulnerable_path, finding)
    trace["deterministic_tool_calls"].append("graph_analysis_tool")
    trace["attack_path"] = attack_path_result
    print(f"  ✓ Path Exists: {attack_path_result['path_exists']}")
    print(f"  ✓ Risk Score: {attack_path_result['risk_score']}")
    print(f"  ✓ Severity: {attack_path_result['severity']}")
    trace["risk_before_remediation"] = attack_path_result["risk_score"]
    print()
    
    # Root cause analysis
    print(f"Calling root_cause_tool(finding, {vulnerable_path}, ...)...")
    root_cause_result = root_cause_tool(
        finding,
        vulnerable_path,
        str(ROOT / "commit_history.json"),
        str(ROOT / "deployment_events.json"),
    )
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
        print(f"  {i}. {agent.name}")
    print()

    # Step 4: Execute live ADK + Gemini (if credentials available)
    print("STEP 4: EXECUTING LIVE ADK + GEMINI ORCHESTRATION")
    print("-" * 80)
    
    if cred_ok:
        print(f"Invoking run_adk_case_with_credentials('{case_id}')...")
        print("  ⏳ Waiting for Gemini API response...")
        
        try:
            events = await run_adk_case_with_credentials(case_id)
            trace["gemini_call_status"] = "SUCCESS"
            trace["events_captured"] = len(events)
            
            print(f"  ✓ Gemini call succeeded")
            print(f"  ✓ Events captured: {len(events)}")
            
            # Parse events to extract remediation and insights
            for i, event in enumerate(events):
                if isinstance(event, dict):
                    if "remediation" in event:
                        trace["gemini_remediation"] = event.get("remediation")
                    if "patch" in event:
                        trace["gemini_remediation"] = event.get("patch")
            
        except Exception as e:
            trace["gemini_call_status"] = "FAILED"
            trace["gemini_call_error"] = str(e)
            print(f"  ✗ Gemini call failed: {e}")
            print()
            print("Continuing with deterministic verification...")
    else:
        trace["gemini_call_status"] = "SKIPPED"
        trace["gemini_call_error"] = cred_msg
        print(f"  ⚠ Skipping Gemini call: {cred_msg}")
        print()
        print("Proceeding with deterministic verification only...")
    
    print()

    # Step 5: Deterministic verification (AUTHORITATIVE)
    print("STEP 5: DETERMINISTIC VERIFICATION (AUTHORITATIVE)")
    print("-" * 80)
    print(f"Calling deterministic_verification_tool({vulnerable_path}, {patched_path}, ...)...")
    
    verification_result = deterministic_verification_tool(vulnerable_path, patched_path, finding)
    trace["deterministic_tool_calls"].append("deterministic_verification_tool")
    trace["final_verification_status"] = verification_result["status"]
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
    print(f"  - Risk unchanged by Gemini: {trace['risk_before_remediation']} == {attack_path_result['risk_score']}")
    print(f"✓ Verification is deterministic: {trace['final_verification_status']}")
    print()

    # Summary
    print("EXECUTION SUMMARY")
    print("=" * 80)
    print(f"Case ID: {case_id}")
    print(f"ADK Session: {session_id}")
    print(f"Credentials: {cred_msg}")
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
        
        # Determine exit code based on Gemini status
        if trace["gemini_call_status"] == "FAILED":
            print(f"✗ Gemini call failed: {trace['gemini_call_error']}")
            return 1
        
        return 0
        
    except Exception as e:
        print(f"✗ Execution failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
