# Phase 6: Architecture Analysis - Gemini Quota Optimization

**Status:** Analysis Only - NO LIVE CALLS  
**Date:** 2026-08-29

---

## Current Problem

**Live Execution Result:** `429 RESOURCE_EXHAUSTED`
- Free-tier quota: 5 requests per minute
- gemini-3.6-flash used up quota in single test run
- SequentialAgent architecture requires 5 Gemini calls

---

## Current Architecture Analysis

### ADK Workflow - 5-Agent Sequential Pipeline

```
┌─────────────────────────────────────────────────────────┐
│ SequentialAgent: aegis_day3_workflow                    │
│                                                         │
│  1. find_investigation_agent (LlmAgent)                │
│     ├─ NO TOOLS                                         │
│     └─ GEMINI CALL #1: Validate finding ID             │
│                                                         │
│  2. attack_path_agent (LlmAgent with tools)            │
│     ├─ TOOL: graph_analysis_tool(finding_id)           │
│     └─ GEMINI CALL #2: Interpret attack path           │
│                                                         │
│  3. root_cause_agent (LlmAgent with tools)             │
│     ├─ TOOL: root_cause_tool(finding_id)               │
│     └─ GEMINI CALL #3: Explain root cause              │
│                                                         │
│  4. remediation_agent (LlmAgent)                        │
│     ├─ NO TOOLS                                         │
│     └─ GEMINI CALL #4: Draft patch proposal            │
│                                                         │
│  5. verification_agent (LlmAgent with tools)           │
│     ├─ TOOL: deterministic_verification_tool(...)      │
│     └─ GEMINI CALL #5: Report verification results    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Request Count Analysis

| Agent | Type | Tools | Gemini Calls | Observation |
|-------|------|-------|--------------|------------|
| find_investigation | LlmAgent | None | 1 | Pure validation - NO generative value |
| attack_path | LlmAgent | graph_analysis_tool | 1 | Interprets deterministic result - MARGINAL value |
| root_cause | LlmAgent | root_cause_tool | 1 | Interprets deterministic result - MARGINAL value |
| remediation | LlmAgent | None | 1 | Generates proposal - ESSENTIAL ✓ |
| verification | LlmAgent | deterministic_verification_tool | 1 | Reports deterministic result - NO generative value |
| **Total** | | | **5** | **Excessive for free tier** |

---

## Critical Flaw: Remediation Verification Mismatch

### Current Verification Flow

1. **Gemini remediation_agent** generates patch proposal → stored in agent output
2. **Deterministic tool** always verifies **main.patched.tf** (canonical fixture)
3. **Result:** Trace shows "VERIFIED" but it's verifying the FIXTURE, not Gemini's proposal
4. **Trust Violation:** No connection between Gemini's proposal and verification result

### Code Evidence

`run_local_case()` line 155-157:
```python
remediation = {
    "patch": _minimal_remediation(vulnerable_path),  # Uses fixture remediation
    ...
}
verification = deterministic_verification_tool(finding_id)  # Verifies main.patched.tf fixture
```

**The verification result does NOT evaluate Gemini's proposed remediation.**

---

## Proposed Optimized Architecture

### MVP Design: Minimal Gemini Calls

```
┌────────────────────────────────────────────────────────────┐
│ DETERMINISTIC STAGE 1: Finding Validation (NO GEMINI)     │
├────────────────────────────────────────────────────────────┤
│ • Load finding.json                                        │
│ • Validate finding_id schema                              │
│ • Return: investigation_context                           │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ DETERMINISTIC STAGE 2: Attack Path (NO GEMINI)            │
├────────────────────────────────────────────────────────────┤
│ • Call graph_analysis_tool(finding_id) directly           │
│ • Return: attack_path_context                             │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ DETERMINISTIC STAGE 3: Root Cause (NO GEMINI)             │
├────────────────────────────────────────────────────────────┤
│ • Call root_cause_tool(finding_id) directly               │
│ • Return: root_cause_context                              │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ GENERATIVE STAGE 4: Remediation (*** ONLY GEMINI ***)     │
├────────────────────────────────────────────────────────────┤
│ • ONE Gemini remediation_agent call                       │
│ • Input: attack_path_context + root_cause_context        │
│ • Output: proposed remediation patch                      │
│ • GEMINI CALL #1 (and only call)                          │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ DETERMINISTIC STAGE 5: Verification (NO GEMINI)           │
├────────────────────────────────────────────────────────────┤
│ • Parse Gemini remediation proposal                       │
│ • Create candidate patch in controlled workspace          │
│ • Call analyze_security on candidate patch                │
│ • Compare risk: before/after                              │
│ • Determine: VERIFIED or REJECTED                         │
│ • VERIFY GEMINI'S PROPOSAL (not fixture)                  │
└────────────────────────────────────────────────────────────┘
```

### Request Count: Current vs. Proposed

| Stage | Current | Proposed | Change |
|-------|---------|----------|--------|
| Finding | 1 Gemini call (LLM) | Direct load | **-1** |
| Attack Path | 1 Gemini call (interprets tool) | Direct call | **-1** |
| Root Cause | 1 Gemini call (interprets tool) | Direct call | **-1** |
| Remediation | 1 Gemini call (generates proposal) | 1 Gemini call | **0** |
| Verification | 1 Gemini call (reports result) | Direct verification | **-1** |
| **Total** | **5 Gemini calls** | **1 Gemini call** | **-80%** ✅ |

---

## Architecture Comparison

### BEFORE: 5-Agent Sequential (Current)

**Advantages:**
- All stages use ADK + Gemini uniformly
- Conceptually clean pipeline

**Disadvantages:**
- ❌ Hits free-tier quota immediately
- ❌ Remediation verification doesn't verify Gemini proposal
- ❌ 4 agents do purely deterministic or interpretive tasks (waste of Gemini calls)
- ❌ Feedback loop slow due to sequential LLM calls
- ❌ No distinction between where value comes from

### AFTER: Hybrid Deterministic + Generative (Proposed)

**Advantages:**
- ✅ Only 1 Gemini call (remediation)
- ✅ Verification directly connects to Gemini proposal
- ✅ Deterministic stages fast and quota-independent
- ✅ Clear separation of trust boundaries
- ✅ Trace accurately reflects what was verified
- ✅ ADK still used for orchestration + remediation agent

**Disadvantages:**
- Requires custom orchestration (not pure SequentialAgent)
- Remediation parsing more complex
- Must create controlled workspace for candidate patches

**Trade-off:** Worth it for correctness and quota efficiency.

---

## Implementation Plan

### Stage 1: Deterministic-First Execution
**File:** `day3_workflow.py`
- Extract deterministic tools into orchestration function
- Call graph_analysis_tool, root_cause_tool directly (no Gemini)
- Collect results for remediation context

### Stage 2: Single Gemini Remediation Agent
**File:** `day3_workflow.py`
- Keep remediation_agent as LlmAgent
- Input: investigation + attack_path + root_cause context
- Output: remediation proposal

### Stage 3: Candidate Patch Verification
**File:** `day3_workflow.py` + new helper
- Parse Gemini remediation output
- Extract Terraform changes
- Create candidate patch in temp/controlled location
- Verify deterministically (DON'T use fixture)

### Stage 4: Trace Structure
**File:** `live_execution_trace.py`
- Distinguish gemini_call_status vs. deterministic_result
- Show candidate_patch_verified (did Gemini's patch work?)
- Clear separation of VERIFIED vs. NOT_VERIFIED

### Stage 5: Error Handling
**File:** `day3_workflow.py`
- Catch 429 RESOURCE_EXHAUSTED gracefully
- Preserve deterministic investigation results
- Mark remediation as QUOTA_EXCEEDED, not REJECTED
- Provide retry information

---

## Test Coverage

### New Tests

1. **test_deterministic_stages_work_without_gemini**
   - Run investigation + attack path + root cause
   - Verify no Gemini calls made
   - Check results are correct

2. **test_gemini_remediation_only**
   - Verify only remediation stage calls Gemini
   - Check 1-call limit

3. **test_verification_validates_gemini_proposal_not_fixture**
   - Parse Gemini proposal
   - Create candidate patch
   - Verify against candidate (not main.patched.tf fixture)
   - Assert verification result depends on Gemini output

4. **test_verification_fails_if_gemini_proposal_bad**
   - Mock Gemini proposal with bad patch
   - Verify that verification returns NOT_VERIFIED
   - (This confirms we're actually verifying Gemini output)

5. **test_quota_exceeded_preserves_deterministic_results**
   - Mock 429 response after deterministic stages
   - Verify investigation/attack_path/root_cause still in trace
   - Verify remediation marked QUOTA_EXCEEDED

6. **test_trace_distinguishes_verified_vs_quoted_status**
   - Check gemini_call_status, candidate_patch_verified, final_verification_status
   - Ensure VERIFIED doesn't imply Gemini proposal was verified

---

## Files to Modify

1. **day3_workflow.py** (Major changes)
   - Refactor run_adk_case() for hybrid architecture
   - Remove 4 unnecessary LlmAgents (keep only remediation_agent)
   - Add deterministic orchestration
   - Add Gemini remediation call
   - Add candidate patch verification
   - Add 429 error handling

2. **live_execution_trace.py** (Update trace structure)
   - Add fields: candidate_patch_generated, candidate_patch_verified
   - Clarify gemini_call_status, remediation_source
   - Distinguish VERIFIED from QUOTA_EXCEEDED

3. **test_day3_acceptance.py** (Add 6 new tests + update existing)
   - Test deterministic-first execution
   - Test single Gemini call
   - Test candidate patch verification
   - Test quota error handling

---

## What Stays Unchanged

- ✅ finding_id secure contract (Phase 5)
- ✅ Risk formula: 87 for public+sensitive buckets
- ✅ Attack-path algorithm
- ✅ Terraform parsing
- ✅ Root-cause correlation
- ✅ Scenario data (finding.json, main.tf, main.patched.tf)
- ✅ Gemini model: gemini-3.6-flash
- ✅ Five logical AEGIS stages (FIND, ATTACK PATH, ROOT CAUSE, REMEDIATION, VERIFY)
- ✅ Google ADK framework (still used for orchestration + remediation agent)
- ✅ Deterministic security logic (unchanged, just called directly)

---

## Next Steps

1. Update `day3_workflow.py` with hybrid architecture
2. Add candidate patch verification logic
3. Update `live_execution_trace.py` trace structure
4. Add 6 new tests
5. Run full test suite
6. Report findings and readiness

---

## Success Criteria

- ✅ Only 1 Gemini API call (remediation)
- ✅ Deterministic stages run without Gemini
- ✅ Verification directly validates Gemini proposal (not fixture)
- ✅ Trace accurately reflects verification target
- ✅ All 43+ tests pass
- ✅ 429 quota error handled gracefully
- ✅ Five logical stages still visible in trace
- ✅ ADK still used for orchestration
