#!/usr/bin/env python3
"""Run the native desktop domain/process matrix, retain auditable public logs.

Linux: python3 scripts/desktop-e2e.py --output /tmp/desktop-e2e
Windows: py -3 scripts/desktop-e2e.py --output "$env:TEMP/desktop-e2e"
macOS arm64: python3 scripts/desktop-e2e.py --output /tmp/desktop-e2e

Requires the same GPUI build dependencies as the documented GUI checks. This
runs real isolated OS processes/loopback, never claims native UI or dual NAT.
Original CLI E2E remains scripts/e2e.sh and must run separately after cargo build.
"""
import argparse
import datetime
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
import time

CASES = {
    "unconfigured-restored-identity": ["three_process_passive_directory_collision_and_signal_restart", "settings_roundtrip_and_atomic_replacement", "corrupt_config_is_reported_and_never_overwritten"],
    "passive-two-and-three-process": ["three_process_passive_directory_collision_and_signal_restart", "passive_peer_uses_same_registration_and_third_peer_progresses", "explicit_mapping_refresh_preserves_unchanged_authenticated_connection"],
    "file-directory-integrity": ["three_process_passive_directory_collision_and_signal_restart", "authenticated_single_file_and_empty_file_complete_with_durable_receipts"],
    "sender-receiver-simultaneous-pause": ["two_process_pause_both_sides_and_storage_source_errors_reach_ui", "pause_racing_last_chunk_preserves_completed_receipt", "pause_timeout_retains_download_and_marks_interrupted"],
    "os-kill-manual-continue": ["session_process_kill_either_endpoint_restart_requires_manual_continue", "real_process_kill_of_either_endpoint_resumes_verified_durable_chunks"],
    "publication-boundary-os-kill": ["os_kill_at_every_publication_boundary_preserves_old_new_and_single_receipt"],
    "collision-receipt-idempotence": ["three_process_passive_directory_collision_and_signal_restart", "lost_completed_frame_replays_receipt_without_republishing", "timestamp_collision_preserves_occupied_backup_and_retries_fixed_suffix"],
    "concurrency-one-two-three-shrink": ["real_queue_runs_one_two_three_files_on_the_same_authenticated_peer", "lowering_three_to_one_does_not_kill_or_refill_excess_activity", "blocked_file_does_not_stop_ready_file_and_pause_releases_pending_slot"],
    "byte-fairness-and-slow-writer": ["continuously_ready_writers_have_a_byte_bound_even_with_different_short_writes", "synchronously_ready_async_loops_yield_and_remain_byte_fair", "blocked_writer_releases_turn_and_unused_share_is_borrowed_without_credit_growth"],
    "source-storage-network-signal-errors": ["two_process_pause_both_sides_and_storage_source_errors_reach_ui", "session_process_kill_either_endpoint_restart_requires_manual_continue", "three_process_passive_directory_collision_and_signal_restart", "permissions_failure_keeps_recovery_and_does_not_commit_receipt", "receiver_continue_reports_previously_detected_source_change"],
    "security-boundaries": ["paths_are_relative_portable_and_never_silently_rewritten", "source_symlink_and_normalization_or_case_collision_are_rejected", "malicious_manifest_path_trailing_bytes_and_bitmap_are_rejected", "oversized_length_header_fails_without_waiting_for_payload", "unexpected_authenticated_target_fails_before_connected"],
    "old-desktop-explicit-rejection": ["unsupported_version_missing_capability_and_old_cli_are_explicit_errors", "authenticated_legacy_peer_is_rejected_by_desktop_negotiation", "schema_only_speed_capability_cannot_negotiate_the_execution_business"],
    "speed-file-arbitration-and-cancel": ["speed_cancel_and_stale_uni_token_do_not_pollute_next_test_or_file_transfer", "speed_and_file_activity_exclude_each_other_without_silent_pause", "speed_simultaneous_requests_have_one_grant_and_one_busy"],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=None, help="new or empty evidence directory outside the checkout")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parent.parent
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="desktop-e2e-"))
    # Never overwrite evidence, and never create untracked test outputs in source.
    if output == repo or repo in output.parents:
        parser.error("output must be outside the checkout")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        parser.error("output directory must be empty; old failure logs must be preserved")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=repo))
    command = ["cargo", "test", "--locked", "--offline", "--features", "gui", "--lib", "desktop::", "--", "--nocapture"]
    started = datetime.datetime.now(datetime.timezone.utc).isoformat()
    begin = time.monotonic()
    log_file = output / "desktop.log"
    with log_file.open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT)
    text = log_file.read_text(encoding="utf-8", errors="replace")
    passed = set(re.findall(r"test (desktop::[\w:]+) \.\.\. ok", text))
    proofs = []
    for line in text.splitlines():
        marker = "DESKTOP_E2E_PROOF "
        if marker in line:
            proofs.append(json.loads(line.split(marker, 1)[1]))
    cases = []
    if sys.platform != "linux":
        CASES["security-boundaries"].remove("source_symlink_and_normalization_or_case_collision_are_rejected")
        CASES["security-boundaries"].append("collision_keys_detect_case_and_unicode_normalization_on_all_platforms")
        if sys.platform == "win32":
            CASES["security-boundaries"].append("windows_source_junction_and_receive_reparse_directory_are_rejected")
    if sys.platform != "win32":
        CASES["security-boundaries"].append("staging_part_and_bitmap_symlinks_cannot_touch_unselected_files")
    CASES["source-storage-network-signal-errors"].append(
        "windows_open_target_failure_keeps_old_file_and_can_retry_after_release"
        if sys.platform == "win32" else "actual_unix_receive_permission_failure_reaches_ui_and_retry_preserves_old_file"
    )
    for scenario, required in CASES.items():
        missing = [name for name in required if not any(p.endswith("::" + name) for p in passed)]
        cases.append({"scenario": scenario, "result": "PASS" if not missing and result.returncode == 0 else "FAIL", "required_tests": required, "missing": missing, "evidence": "desktop.log"})
    boundary = {p["detail"]["boundary"] for p in proofs if p["scenario"] == "publication-os-kill"}
    kills = {p["detail"]["killed"] for p in proofs if p["scenario"] == "session-os-kill-manual-continue"}
    pause = {p["detail"]["initiator"] for p in proofs if p["scenario"] == "process-pause-continue"}
    proof_complete = len(boundary) == 10 and kills == {"a", "b"} and pause == {"sender", "receiver", "simultaneous"}
    ignored = re.search(r"test result: ok\. \d+ passed; 0 failed; 0 ignored", text) is not None
    success = result.returncode == 0 and ignored and proof_complete and all(c["result"] == "PASS" for c in cases)
    matrix = {"schema": "desktop-e2e/v1", "head_sha": head, "working_tree_dirty": dirty, "platform": platform.platform(), "architecture": platform.machine(), "started_utc": started, "elapsed_seconds": round(time.monotonic()-begin, 3), "command": command, "exit_code": result.returncode, "result": "PASS" if success else "FAIL", "cases": cases, "process_proofs": proofs, "proof_complete": proof_complete, "limits": ["Process actors execute production DesktopSession, not GPUI window automation.", "StorageFull/PermissionDenied injection is modeled I/O; Unix chmod denial and Windows occupied-target denial are distinct actual platform tests.", "Controlled writer fairness is not a physical bandwidth threshold.", "Loopback/CI are not physical Win10/11, Apple Silicon interaction or dual NAT.", "CLI compatibility/core tests and scripts/e2e.sh run separately after rebuild; this script does not claim them."]}
    (output / "matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, indent=2)+"\n", encoding="utf-8")
    print(json.dumps({"result": matrix["result"], "head_sha": head, "working_tree_dirty": dirty, "platform": matrix["platform"], "elapsed_seconds": matrix["elapsed_seconds"], "evidence": str(output), "cases": len(cases), "process_proofs": len(proofs)}, ensure_ascii=False))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
