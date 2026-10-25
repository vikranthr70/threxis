"""Streamlit controls and views over contributor backend outputs."""
from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from src.common.models import ContractError, SelectionStrategy
from src.ui.theme import apply_theme, favicon, instrument, page_header, statistic
from src.ui.live import monitor_snapshot, LOG_PATH
from src.ui.service import SCENARIOS, build_workspace, build_workspace_from_events, case_outputs, load_research_records, preserve_selected
from src.readiness.assessment import aggregate_readiness, simulate_readiness_improvement, STATUS_FACTORS
from src.readiness.selectors import rank_candidates
from src.forensics.audit import read_audit_trail

ROOT = Path(__file__).resolve().parents[2]
PAGES = ["Live Ubuntu Monitor", "Command Center", "Forensic Readiness", "Threat Detection", "Evidence Prioritization",
         "Incident Investigation", "Evidence Vault", "Research Evaluation", "Launch Status",
         "Privacy Policy", "Terms and Conditions"]


def table(rows):
    if rows:
        st.dataframe(rows, hide_index=True, width="stretch")
    else:
        st.info("No records for this view.")


def reset_vault():
    preserved = st.session_state.pop("preserved", None)
    if preserved:
        preserved.close()
    st.session_state.pop("verification", None)


def workspace(scenario, count, seed):
    unavailable_key = f"unavailable_{scenario}_{seed}_{count}"
    preferences = st.session_state.setdefault("workspace_preferences", {})
    unavailable = tuple(preferences.get(unavailable_key, []))
    budget = int(preferences.get("budget", 10))
    ws = build_workspace(scenario, count, seed, unavailable, budget)
    signature = (scenario, seed, count, unavailable, budget)
    if st.session_state.get("workspace_signature") != signature:
        reset_vault()
        st.session_state["workspace_signature"] = signature
    return ws, unavailable_key


def recommendations(ws):
    st.subheader("Weighted readiness gaps")
    table([row for row in ws["details"]["weighted_readiness_gaps"] if row["weighted_gap"] > 0])
    for action in ws["details"]["recommended_actions"]:
        st.write(action)
    st.caption("Generic backend recommendations. The table orders requirements by weighted gap.")


@st.fragment(run_every="3s")
def live_snapshot_panel():
    """Auto-refresh the operator-supplied Ubuntu log file."""
    snapshot = monitor_snapshot()
    if not snapshot["path_exists"]:
        st.info("WAITING FOR UBUNTU LOG SOURCE: data/live/ubuntu-auth.log")
        return
    events, alerts = snapshot["events"], snapshot["alerts"]
    left, right = st.columns(2)
    with left:
        statistic("Observed SSH failures", len(events))
    with right:
        statistic("Detection alerts", len(alerts))
    if alerts:
        st.error("SSH FAILURE BURST DETECTED")
        st.caption("Suspicious authentication pattern. Not proof of account compromise.")
    elif events:
        st.info("Authentication failures observed. No rule threshold met yet.")
    else:
        st.info("Log source connected. Waiting for SSH failed-password records.")
    if events:
        ws = build_workspace_from_events(events, budget=10)
        st.subheader("Forensic readiness / observed evidence")
        instrument(ws["details"])
        st.subheader("Priority evidence / adaptive selection")
        selected = next(item for item in ws["comparisons"] if item.strategy is SelectionStrategy.ADAPTIVE)
        st.caption(f"Selected {len(selected.selected_evidence_ids)} observed records within {selected.budget} collection cost units.")
        table([{"evidence_id": item.evidence_id, "source": item.source_type,
                "collection_cost": item.collection_cost,
                "priority": "SELECTED" if item.evidence_id in selected.selected_evidence_ids else "NOT SELECTED"}
               for item in ws["candidates"]])
        st.subheader("MITRE ATT&CK mappings")
        table(ws["mappings"])
        st.subheader("Incident timeline")
        table([item.to_dict() for item in ws["timeline"][-30:]])
        if st.button("Preserve prioritized Ubuntu evidence"):
            reset_vault()
            st.session_state["live_preserved"] = preserve_selected(ws, SelectionStrategy.ADAPTIVE)
        preserved = st.session_state.get("live_preserved")
        if preserved:
            if st.button("Verify preserved Ubuntu evidence SHA-256"):
                st.session_state["live_verification"] = preserved.verify()
            verification = st.session_state.get("live_verification")
            if verification:
                st.write(verification)
            record, report = case_outputs(ws, preserved, verification)
            st.download_button("Download Ubuntu investigation report", report,
                               "ubuntu-investigation.md", "text/markdown")
            st.download_button("Download preserved Ubuntu evidence", preserved.archive(),
                               "ubuntu-evidence.zip", "application/zip")
    st.subheader("Detection alerts")
    table([alert.to_dict() for alert in alerts])
    st.subheader("Recent authentication events")
    table([event.to_dict() for event in events[-100:]])
    st.caption("This panel refreshes every 3 seconds. Only actual imported Ubuntu log records are shown. "
               "No synthetic events are mixed into the live view.")


def live_monitor():
    page_header("00 / LIVE INCIDENT CONSOLE", "Ubuntu Security Monitor",
                "Observe failed SSH login attempts on your own VirtualBox Ubuntu VM.")
    st.caption("LIVE LOG FEED / AUTHENTICATION / READ ONLY")
    st.write("Start your Ubuntu VM, perform three manual failed SSH login attempts against "
             "a nonexistent test account, and inspect the resulting rule alert.")
    with st.expander("VirtualBox connection instructions"):
        st.write("Use an isolated host-only VM network. Export Ubuntu sshd failed-password "
                 "log lines into data/live/ubuntu-auth.log on this computer. "
                 "The dashboard reads this file automatically every three seconds. "
                 "See docs/ubuntu-live-demo.md for detailed instructions.")
    live_snapshot_panel()


def overview(ws):
    page_header("01 / OVERVIEW", "Evidence before conclusions.",
                "Assess forensic readiness, examine synthetic threats, and preserve the evidence that supports an investigation.")
    left, right = st.columns([1.35, 1], gap="large")
    with left:
        instrument(ws["details"])
    with right:
        st.markdown('<div class="eyebrow">CURRENT CASE / SYNTHETIC</div>', unsafe_allow_html=True)
        st.subheader(SCENARIOS[ws["scenario"]])
        st.caption(ws["case"].case_id)
        a, b = st.columns(2)
        with a: statistic("Generated events", len(ws["events"]))
        with b: statistic("Heuristic alerts", len(ws["alerts"]))
        a, b = st.columns(2)
        with a: statistic("Supported mappings", len(ws["mappings"]))
        with b: statistic("Unknown sources", len(ws["details"]["unknown_evidence"]))
        st.write("Every value comes from the current synthetic workspace. Readiness describes source preparedness for this scenario.")
        st.caption("Inspect source requirements in Forensic Readiness, then apply a collection budget in Evidence Prioritization.")
    st.divider()
    columns = st.columns(3, gap="large")
    for col, index, title, text in zip(columns, ["01", "02", "03"],
            ["Assess the sources", "Select within budget", "Preserve and examine"],
            ["Inspect status factors, source contributions, and weighted gaps for the active threat context.",
             "Compare five strategies using the same eligible artifacts and collection costs.",
             "Copy synthetic records, verify SHA-256, and export an evidence-linked case report."]):
        with col:
            st.markdown(f'<div class="index-number">{index}</div>', unsafe_allow_html=True)
            st.subheader(title)
            st.write(text)


def readiness(ws, count, seed):
    page_header("02 / PREPAREDNESS", "Forensic Readiness",
                "A source-by-source assessment of the evidence available to investigate the current scenario.")
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        instrument(ws["details"])
        st.caption(f'Assessment: {ws["readiness"].assessment_id}')
    with right:
        source = st.selectbox("Inspect evidence source", list(ws["profile"].evidence_weights),
                              key=f'inspect_{ws["scenario"]}')
        row = next(item for item in ws["details"]["requirements"] if item["source_type"] == source)
        gap = next(item["weighted_gap"] for item in ws["details"]["weighted_readiness_gaps"] if item["source_type"] == source)
        with st.container(border=True):
            st.subheader(source.replace("_", " ").title())
            st.write(f'Current status: **{row["status"].replace("_", " ").upper()}**')
            table([{"Context weight": row["weight"], "Status factor": row["status_factor"],
                    "Weighted contribution": row["weighted_contribution"], "Weighted gap": gap}])
            action = next((x for x in ws["details"]["recommended_actions"] if source in x), None)
            st.write(action or "No missing or unknown-source action was returned by the backend.")
        with st.expander("Observed artifact references"):
            st.write(list(ws["source_trace"].get(source, ())) or "No observed artifacts.")
    st.subheader("Hypothetical improvement")
    st.caption("Explore a hypothetical status change. The simulator leaves observations and system settings unchanged.")
    a, b = st.columns(2)
    with a:
        sim_source = st.selectbox("Source to simulate", list(ws["profile"].evidence_weights),
                                 key=f'sim_source_{ws["scenario"]}')
    current = ws["statuses"].get(sim_source, "unknown")
    choices = [value for value in ("available", "collected", "validated")
               if STATUS_FACTORS[value] > (STATUS_FACTORS[current] or 0)]
    with b:
        new = st.selectbox("Hypothetical status", choices or ["validated"],
                           key=f'sim_status_{ws["scenario"]}_{sim_source}')
    result = simulate_readiness_improvement(ws["profile"], ws["statuses"], {sim_source: new})
    a, b, c = st.columns(3)
    with a: statistic("Current readiness", f'{result["original_readiness"]["readiness_percentage"]:.1f}%')
    with b: statistic("Simulated readiness", f'{result["simulated_readiness"]["readiness_percentage"]:.1f}%')
    with c: statistic("Change / percentage points", f'{result["percentage_point_difference"]:+.1f}')
    st.caption(f"Hypothetical change: {sim_source} from {current} to {new}.")
    st.write(ws["details"]["scoring_explanation"])
    with st.expander("Text and table equivalent / scoring methodology"):
        table(ws["details"]["requirements"])
        st.write(ws["details"]["model_limit"])
        st.json(ws["readiness"].to_dict())
    recommendations(ws)
    st.subheader("Scenario comparison")
    details = [ws["details"] if scenario == ws["scenario"] else build_workspace(scenario, count, seed, budget=0)["details"]
               for scenario in SCENARIOS]
    summary = aggregate_readiness(details)
    table([{"Scenario": SCENARIOS[row["scenario_id"]], "Readiness (%)": row["readiness_percentage"]} for row in details])
    st.caption("Fresh observations for each scenario; artifact exclusions apply only to the active instance.")
    st.caption(f'Overall {summary["overall_readiness_percentage"]:.1f}%: {summary["aggregation_method"]}.')


def detection(ws):
    page_header("03 / SIGNAL REVIEW", "Threat Detection",
                "Inspect heuristic alerts and supported MITRE ATT&CK candidates from the current synthetic records.")
    levels = st.multiselect("Filter alert severity", ["low", "medium", "high", "critical"],
                            default=["low", "medium", "high", "critical"])
    table([item.to_dict() for item in ws["alerts"] if item.severity.value in levels])
    st.subheader("MITRE ATT&CK candidates")
    table(ws["mappings"])
    st.caption("Only supported backend rules emit mappings. No mapping is a valid outcome. Confidence describes ordinal rule support.")
    st.subheader("Synthetic event records")
    table([item.to_dict() for item in ws["events"]])


def prioritization(ws, key, count, seed):
    page_header("04 / COLLECTION PLANNING", "Evidence Prioritization",
                "Apply a collection budget to five strategies using the same eligible artifacts.")
    preferences = st.session_state["workspace_preferences"]
    def store_unavailable():
        preferences[key] = list(st.session_state["_unavailable"])
    def store_budget():
        preferences["budget"] = int(st.session_state["_budget"])
    st.multiselect("Mark synthetic artifacts unavailable", [item.evidence_id for item in ws["candidates"]],
                   default=preferences.get(key, []), key="_unavailable", on_change=store_unavailable)
    st.number_input("Collection budget (cost units)", min_value=0, max_value=1000,
                    value=preferences.get("budget", 10), step=1, key="_budget", on_change=store_budget)
    ws, _ = workspace(ws["scenario"], count, seed)
    name = st.selectbox("Inspect strategy", [item.value for item in SelectionStrategy], key="strategy")
    result = next(item for item in ws["comparisons"] if item.strategy.value == name)
    a, b, c = st.columns(3)
    with a: statistic("Eligible artifacts", sum(ws["flags"].values()))
    with b: statistic("Selected artifacts", len(result.selected_evidence_ids))
    with c: statistic("Selected cost / budget", f"{result.selected_cost} / {result.budget}")
    table([{"Strategy": item.strategy.value, "Selected artifacts": len(item.selected_evidence_ids),
            "Cost": item.selected_cost, "Budget": item.budget} for item in ws["comparisons"]])
    st.subheader("Candidate ledger")
    table([dict(item.to_dict(), availability="available" if ws["flags"][item.evidence_id] else "unavailable",
                selected=item.evidence_id in result.selected_evidence_ids) for item in ws["candidates"]])
    if result.strategy is SelectionStrategy.ADAPTIVE:
        eligible = [item for item in ws["candidates"] if ws["flags"][item.evidence_id]]
        ranking = rank_candidates(result.strategy, eligible, ws["profile"], set(), None)
        positions = {value: index + 1 for index, value in enumerate(ranking)}
        st.subheader("Adaptive ranking explanation")
        table([{"Evidence ID": item.evidence_id, "Source": item.source_type,
                "Context weight": ws["profile"].evidence_weights.get(item.source_type, 0),
                "Cost": item.collection_cost,
                "Weight per cost": ws["profile"].evidence_weights.get(item.source_type, 0) / item.collection_cost,
                "Rank": positions[item.evidence_id],
                "Budget impact": item.collection_cost if item.evidence_id in result.selected_evidence_ids else 0,
                "Reason": "selected" if item.evidence_id in result.selected_evidence_ids else "does not fit remaining budget"}
               for item in sorted(eligible, key=lambda x: positions[x.evidence_id])])
    st.download_button("Download comparison JSON", json.dumps([item.to_dict() for item in ws["comparisons"]], indent=2),
                       "synthetic-selection.json", "application/json")
    st.caption("Rank weights are judgments. These demonstrations do not calculate scientific recall or precision.")


def investigation(ws):
    page_header("05 / CASE REVIEW", "Incident Investigation",
                "Reconstruct the synthetic sequence and examine the facts supporting each investigative hypothesis.")
    record, report = case_outputs(ws, st.session_state.get("preserved"), st.session_state.get("verification"))
    st.caption(ws["case"].case_id)
    st.subheader("Chronological timeline")
    types = st.multiselect("Timeline entry types", ["event", "alert", "case_opened"],
                           default=["event", "alert", "case_opened"])
    table([item.to_dict() for item in ws["timeline"] if item.entry_type in types])
    st.subheader("Correlated event groups")
    table(ws["correlations"])
    st.caption("Rule support identifies related observations. It does not establish compromise.")
    st.subheader("Preservation coverage")
    st.write(f'{len(record["missing_evidence_ids"])} event records have no preserved artifact in this session.')
    a, b = st.columns(2)
    with a: st.download_button("Download case JSON", json.dumps(record, indent=2), "investigation-case.json", "application/json")
    with b: st.download_button("Download Markdown report", report, "investigation-report.md", "text/markdown")
    with st.expander("Read the investigation report"):
        st.markdown(report)


def vault(ws):
    page_header("06 / ARTIFACT INTEGRITY", "Evidence Vault",
                "Preserve selected synthetic records, verify their SHA-256 digests, and export the collection.")
    strategy = st.selectbox("Collection strategy", [item.value for item in SelectionStrategy], index=3, key="vault_strategy")
    result = next(item for item in ws["comparisons"] if item.strategy.value == strategy)
    st.caption(f"{len(result.selected_evidence_ids)} artifacts selected; {result.selected_cost} cost units within {result.budget}.")
    if st.button("Preserve selected synthetic evidence", disabled=not result.selected_evidence_ids):
        reset_vault()
        st.session_state["preserved"] = preserve_selected(ws, SelectionStrategy(strategy))
        st.session_state["preserved_strategy"] = strategy
        st.success("Selected synthetic records copied to this session's temporary vault.")
    preserved = st.session_state.get("preserved")
    if preserved is None:
        st.info("No evidence has been preserved in this session. Select a strategy and preserve its chosen artifacts.")
        return
    st.caption("Preserved using: " + st.session_state["preserved_strategy"])
    table([item.to_dict() for item in preserved.manifests])
    if st.button("Recalculate SHA-256 and verify"):
        st.session_state["verification"] = preserved.verify()
    verification = st.session_state.get("verification")
    if verification:
        st.subheader("Verification result")
        table(verification["results"])
        st.caption(f'Valid {verification["valid"]} / Modified {verification["modified"]} / Missing {verification["missing"]} / Invalid manifests {verification["invalid_manifests"]}')
    else:
        st.warning("Preserved artifacts have not yet been independently verified.")
    st.download_button("Download evidence ZIP", preserved.archive(), "synthetic-evidence.zip", "application/zip")
    st.subheader("Verification audit")
    table(read_audit_trail(preserved.vault / "verification-audit.jsonl"))
    with st.expander("Collection audit"):
        table(read_audit_trail(preserved.vault / "custody.jsonl"))
    st.caption("Temporary vault files are cleared when the workspace changes. Downloads remain on your device. Local audit records can be modified and are not tamper-proof.")


def research():
    page_header("07 / SAVED RESULTS", "Research Evaluation",
                "Inspect saved experiment records separately from the operational demonstration.")
    st.info("No scientific results are bundled. The experiment runner and frozen main-run results are not available on this branch.")
    upload = st.file_uploader("Load saved EvaluationResult JSONL", type=["jsonl"], max_upload_size=5)
    if upload:
        rows = load_research_records(upload.getvalue())
        st.caption("User-supplied records. Schema validation does not verify provenance, independence, or configuration freeze.")
        table(rows)
    else:
        st.caption("Waiting for saved results. Research metrics and comparative gains are never inferred from demonstration activity.")


def launch():
    page_header("08 / RELEASE GATE", "Public launch status",
                "Local and academic demonstrations can run while release requirements are reviewed.")
    st.error("NOT READY FOR PUBLIC LAUNCH")
    table([
        {"Requirement": "Custom domain / DNS / HTTPS", "Status": "Unverified; no domain supplied"},
        {"Requirement": "Original THREXIS favicon", "Status": "Installed; see browser verification in docs/dashboard.md"},
        {"Requirement": "Application-controlled branding", "Status": "Minimal toolbar; no promotional labels"},
        {"Requirement": "Privacy Policy / Terms", "Status": "Drafts implemented; human review pending"},
        {"Requirement": "Legal navigation", "Status": "Sidebar and footer links"},
        {"Requirement": "Fabricated claims", "Status": "No fabricated research or customer claims"},
        {"Requirement": "Desktop / mobile / controls / tests", "Status": "See actual validation record in docs/dashboard.md"},
    ])


def main():
    st.set_page_config(page_title="THREXIS | Forensic Research", page_icon=favicon(),
                       layout="wide", initial_sidebar_state="auto")
    apply_theme()
    with st.sidebar:
        st.markdown('<div class="wordmark">THREXIS<small>THREAT-INFORMED FORENSIC READINESS</small></div>', unsafe_allow_html=True)
        st.divider()
        requested = st.query_params.get("page", PAGES[0])
        page = st.radio("Workstation navigation", PAGES, index=PAGES.index(requested) if requested in PAGES else 0,
                        key="navigation", label_visibility="collapsed")
        st.divider()
        st.caption("DEMONSTRATION CONTEXT")
        with st.expander("Synthetic demonstration controls", expanded=page != "Live Ubuntu Monitor"):
            scenario = st.selectbox("Threat scenario", list(SCENARIOS), format_func=SCENARIOS.get, key="scenario")
        with st.expander("Advanced: reproducible synthetic data", expanded=False):
            seed = int(st.number_input("Synthetic seed", min_value=0, max_value=1000000, value=25, step=1, key="seed"))
        count = st.select_slider("Event count", options=[6, 12, 18, 24, 36], value=18, key="count")
        if page != "Live Ubuntu Monitor":
            st.caption("Synthetic settings do not affect live Ubuntu monitoring.")
        st.markdown('<div class="launch">NOT READY FOR PUBLIC LAUNCH<br>Local development / academic use</div>', unsafe_allow_html=True)
    try:
        if page in ("Privacy Policy", "Terms and Conditions"):
            page_header("LEGAL / REVIEW DRAFT", page, "Draft for human review before any public launch.")
            st.warning("HUMAN REVIEW PENDING. Operator, contact, jurisdiction, and hosting terms must be completed before publication.")
            path = "privacy.md" if page == "Privacy Policy" else "terms.md"
            st.markdown((ROOT / "docs" / "legal" / path).read_text(encoding="utf-8"))
        elif page == "Live Ubuntu Monitor": live_monitor()
        elif page == "Research Evaluation": research()
        elif page == "Launch Status": launch()
        else:
            ws, unavailable_key = workspace(scenario, count, seed)
            if page == "Command Center": overview(ws)
            elif page == "Forensic Readiness": readiness(ws, count, seed)
            elif page == "Threat Detection": detection(ws)
            elif page == "Evidence Prioritization": prioritization(ws, unavailable_key, count, seed)
            elif page == "Incident Investigation": investigation(ws)
            elif page == "Evidence Vault": vault(ws)
    except (ContractError, OSError, ValueError) as exc:
        st.error(f"Unable to complete this operation: {exc}")
        st.caption("The operation failed. Adjust the inputs or inspect the local server logs.")
    st.markdown('<div class="footer">THREXIS / SYNTHETIC FORENSIC RESEARCH<br>Readiness is a preparedness indicator. Alerts remain investigative hypotheses.</div>', unsafe_allow_html=True)
    st.markdown("[Privacy Policy](?page=Privacy%20Policy) · [Terms and Conditions](?page=Terms%20and%20Conditions) · [Launch Status](?page=Launch%20Status)")
