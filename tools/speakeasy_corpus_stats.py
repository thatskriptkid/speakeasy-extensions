#!/usr/bin/env python3
"""Aggregate Speakeasy corpus batch statistics from saved run artifacts."""
from __future__ import annotations

import argparse
import csv
import json
import statistics
import time
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_ROOT = Path("runs")
CATEGORY_NAMES = (
    "network",
    "files",
    "registry",
    "services",
    "process_injection",
    "crypto",
    "anti_analysis",
    "dropped_artifacts",
)


def _load_json(path: Path | None) -> dict[str, Any]:
    if not path or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return {}


def _first_file(root: Path, pattern: str) -> Path | None:
    found = sorted(root.glob(pattern))
    return found[0] if found else None


def _manifest_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            return list(csv.DictReader(f, delimiter="\t"))
    except Exception:
        return []


def _counter_dict(counter: Counter[Any], limit: int = 50) -> list[dict[str, Any]]:
    return [{"value": str(k), "count": v} for k, v in counter.most_common(limit)]


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct
    lower = int(pos)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return ordered[lower]
    weight = pos - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def _distribution(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "avg": 0, "p50": 0, "p90": 0, "p95": 0, "p99": 0, "max": 0}
    return {
        "count": len(values),
        "avg": round(statistics.fmean(values), 3),
        "p50": round(_percentile(values, 0.50), 3),
        "p90": round(_percentile(values, 0.90), 3),
        "p95": round(_percentile(values, 0.95), 3),
        "p99": round(_percentile(values, 0.99), 3),
        "max": round(max(values), 3),
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _safe_float(value: Any) -> float:
    try:
        return float(value or 0)
    except Exception:
        return 0.0


def _add_indicator(counter: Counter[str], value: Any) -> None:
    if value is None:
        return
    text = str(value).strip()
    if text:
        counter[text] += 1


def _batch_dirs(root: Path, pattern: str) -> list[Path]:
    dirs = []
    for path in sorted(root.glob(pattern)):
        if not path.is_dir():
            continue
        if (path / "selected_manifest.tsv").is_file() or (path / "speakeasy_runs").is_dir():
            dirs.append(path)
    return dirs


def build_stats(root: Path, pattern: str, indicator_limit: int) -> dict[str, Any]:
    dirs = _batch_dirs(root, pattern)
    selected_md5: set[str] = set()
    completed_md5: set[str] = set()
    selected_total = 0
    completed_total = 0
    status_counts: Counter[str] = Counter()
    raw_status_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    triage_counts: Counter[str] = Counter()
    last_api_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    module_counts: Counter[str] = Counter()
    network_indicators: dict[str, Counter[str]] = {
        key: Counter()
        for key in ("urls", "hosts", "domains", "ips", "endpoints", "dns_servers", "resolved_ips")
    }
    dropped_indicators: dict[str, Counter[str]] = {
        key: Counter() for key in ("paths", "pe_like_paths", "sha256")
    }
    category_event_totals: Counter[str] = Counter()
    samples_with_category: Counter[str] = Counter()
    durations: list[float] = []
    api_calls_values: list[float] = []
    behavior_event_values: list[float] = []
    high_signal: list[dict[str, Any]] = []
    long_running: list[dict[str, Any]] = []
    handler_blockers: list[dict[str, Any]] = []
    empty_early: list[dict[str, Any]] = []
    by_dir: list[dict[str, Any]] = []

    for batch_dir in dirs:
        manifest = _manifest_rows(batch_dir / "selected_manifest.tsv")
        selected_total += len(manifest)
        for row in manifest:
            md5 = (row.get("md5") or "").strip().lower()
            if md5:
                selected_md5.add(md5)
            for label in (row.get("labels") or "").split(","):
                if label:
                    label_counts[label] += 1

        dir_rows = []
        dir_network_samples = 0
        dir_behavior_signal = 0
        dir_handler_blockers = 0
        dir_timeouts = 0
        for status_file in sorted((batch_dir / "speakeasy_runs").glob("*/run_status.json")):
            status = _load_json(status_file)
            if not status:
                continue
            run_dir = status_file.parent
            completed_total += 1
            dir_rows.append(status)
            md5 = str(status.get("md5") or "").lower()
            if md5:
                completed_md5.add(md5)
            status_name = str(status.get("status") or "")
            raw_status = str(status.get("raw_status") or status_name)
            blocker = str(status.get("blocker") or "")
            triage = str(status.get("triage_priority") or "")
            last_api = str(status.get("last_api") or "")
            elapsed = _safe_float(status.get("elapsed"))
            api_calls = _safe_int(status.get("api_calls"))
            behavior_events = _safe_int(status.get("behavior_event_count"))
            status_counts[status_name] += 1
            raw_status_counts[raw_status] += 1
            if blocker:
                blocker_counts[blocker] += 1
            if triage:
                triage_counts[triage] += 1
            if last_api:
                last_api_counts[last_api] += 1
            if elapsed:
                durations.append(elapsed)
                long_running.append(
                    {
                        "batch": batch_dir.name,
                        "idx": status.get("idx"),
                        "md5": md5,
                        "filename": status.get("filename"),
                        "elapsed": round(elapsed, 3),
                        "status": status_name,
                        "blocker": blocker,
                    }
                )
            api_calls_values.append(float(api_calls))
            behavior_event_values.append(float(behavior_events))
            if status_name in {"unsupported_api", "api_handler_error", "no_report"}:
                dir_handler_blockers += 1
                handler_blockers.append(
                    {
                        "batch": batch_dir.name,
                        "idx": status.get("idx"),
                        "md5": md5,
                        "filename": status.get("filename"),
                        "status": status_name,
                        "blocker": blocker,
                        "last_api": last_api,
                    }
                )
            if status_name == "timeout":
                dir_timeouts += 1
            if raw_status == "emu_error" and api_calls == 0 and behavior_events == 0:
                empty_early.append(
                    {
                        "batch": batch_dir.name,
                        "idx": status.get("idx"),
                        "md5": md5,
                        "filename": status.get("filename"),
                        "blocker": blocker,
                    }
                )

            behavior = _load_json(_first_file(run_dir, "speakeasy_behavior_*.json"))
            summary = behavior.get("summary") or {}
            counts = summary.get("category_counts") or {}
            if isinstance(counts, dict):
                for category in CATEGORY_NAMES:
                    count = _safe_int(counts.get(category))
                    category_event_totals[category] += count
                    if count > 0:
                        samples_with_category[category] += 1
            if _safe_int(counts.get("network") if isinstance(counts, dict) else 0) > 0:
                dir_network_samples += 1
            if sum(_safe_int((counts or {}).get(c)) for c in CATEGORY_NAMES) > 0:
                dir_behavior_signal += 1

            emu = behavior.get("emulation") or {}
            for module, count in (emu.get("api_calls_by_module") or {}).items():
                module_counts[str(module)] += _safe_int(count)

            categories = behavior.get("categories") or {}
            net = ((categories.get("network") or {}).get("indicators") or {})
            for key, counter in network_indicators.items():
                for value in net.get(key) or []:
                    _add_indicator(counter, value)
            drops = ((categories.get("dropped_artifacts") or {}).get("indicators") or {})
            for key, counter in dropped_indicators.items():
                for value in drops.get(key) or []:
                    _add_indicator(counter, value)

            signal_score = (
                min(api_calls, 1000) / 100.0
                + _safe_int((counts or {}).get("network")) * 5
                + _safe_int((counts or {}).get("dropped_artifacts")) * 5
                + _safe_int((counts or {}).get("process_injection")) * 3
                + _safe_int((counts or {}).get("services")) * 3
                + _safe_int((counts or {}).get("registry")) * 2
                + _safe_int((counts or {}).get("files"))
                + _safe_int((counts or {}).get("crypto"))
                + _safe_int((counts or {}).get("anti_analysis"))
            )
            if signal_score > 0:
                high_signal.append(
                    {
                        "batch": batch_dir.name,
                        "idx": status.get("idx"),
                        "md5": md5,
                        "filename": status.get("filename"),
                        "labels": status.get("labels") or [],
                        "status": status_name,
                        "blocker": blocker,
                        "signal_score": round(signal_score, 1),
                        "api_calls": api_calls,
                        "behavior_events": behavior_events,
                        "network_events": _safe_int(status.get("network_events")),
                        "dropped_artifacts": _safe_int(status.get("dropped_artifacts")),
                        "highlights": (summary.get("highlights") or [])[:5],
                        "run_dir": str(run_dir),
                    }
                )

        by_dir.append(
            {
                "name": batch_dir.name,
                "selected": len(manifest),
                "completed": len(dir_rows),
                "status_counts": dict(Counter(str(row.get("status") or "") for row in dir_rows)),
                "network_samples": dir_network_samples,
                "behavior_signal_samples": dir_behavior_signal,
                "handler_blockers": dir_handler_blockers,
                "timeouts": dir_timeouts,
            }
        )

    high_signal.sort(key=lambda row: float(row["signal_score"]), reverse=True)
    long_running.sort(key=lambda row: float(row["elapsed"]), reverse=True)

    usable_signal = sum(1 for v in behavior_event_values if v > 0)
    api_nonzero = sum(1 for v in api_calls_values if v > 0)
    stats = {
        "generated_at": time.time(),
        "root": str(root),
        "pattern": pattern,
        "batch_dirs": len(dirs),
        "selected_total": selected_total,
        "completed_total": completed_total,
        "unique_selected_md5": len(selected_md5),
        "unique_completed_md5": len(completed_md5),
        "status_counts": dict(status_counts),
        "raw_status_counts": dict(raw_status_counts),
        "stability": {
            "api_nonzero_runs": api_nonzero,
            "behavior_signal_runs": usable_signal,
            "handler_blocker_runs": sum(status_counts.get(s, 0) for s in ("unsupported_api", "api_handler_error", "no_report")),
            "timeout_runs": status_counts.get("timeout", 0),
            "unsupported_format_runs": status_counts.get("unsupported_format", 0),
            "empty_early_emu_errors": len(empty_early),
        },
        "duration_seconds": _distribution(durations),
        "api_calls": _distribution(api_calls_values),
        "behavior_events": _distribution(behavior_event_values),
        "category_event_totals": dict(category_event_totals),
        "samples_with_category": dict(samples_with_category),
        "top_blockers": _counter_dict(blocker_counts, indicator_limit),
        "top_triage_priorities": _counter_dict(triage_counts, indicator_limit),
        "top_last_apis": _counter_dict(last_api_counts, indicator_limit),
        "top_labels": _counter_dict(label_counts, indicator_limit),
        "top_api_modules": _counter_dict(module_counts, indicator_limit),
        "top_network_indicators": {
            key: _counter_dict(counter, indicator_limit) for key, counter in network_indicators.items()
        },
        "top_dropped_artifacts": {
            key: _counter_dict(counter, indicator_limit) for key, counter in dropped_indicators.items()
        },
        "top_high_signal_samples": high_signal[:100],
        "top_long_running_samples": long_running[:100],
        "handler_blocker_samples": handler_blockers[:200],
        "empty_early_samples": empty_early[:200],
        "by_dir": by_dir,
    }
    return stats


def write_markdown(stats: dict[str, Any], path: Path) -> None:
    lines = [
        "# Speakeasy Corpus Statistics",
        "",
        f"- Root: `{stats['root']}`",
        f"- Batch dirs: {stats['batch_dirs']}",
        f"- Selected samples: {stats['selected_total']}",
        f"- Completed run_status artifacts: {stats['completed_total']}",
        f"- Unique selected MD5: {stats['unique_selected_md5']}",
        f"- Unique completed MD5: {stats['unique_completed_md5']}",
        "",
        "## Stability",
        "",
    ]
    for key, value in stats["stability"].items():
        lines.append(f"- `{key}`: {value}")
    lines.extend([
        "",
        "## Status Counts",
        "",
    ])
    for key, value in sorted(stats["status_counts"].items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- `{key or '<empty>'}`: {value}")
    lines.extend([
        "",
        "## Distributions",
        "",
        "- Duration seconds: `" + json.dumps(stats["duration_seconds"], sort_keys=True) + "`",
        "- API calls: `" + json.dumps(stats["api_calls"], sort_keys=True) + "`",
        "- Behavior events: `" + json.dumps(stats["behavior_events"], sort_keys=True) + "`",
        "",
        "## Category Coverage",
        "",
    ])
    for category, count in sorted(stats["samples_with_category"].items()):
        total = stats["category_event_totals"].get(category, 0)
        lines.append(f"- `{category}`: {count} samples, {total} events")
    lines.extend(["", "## Top Blockers", ""])
    for row in stats["top_blockers"][:30]:
        lines.append(f"- `{row['value']}`: {row['count']}")
    lines.extend(["", "## Top Network Indicators", ""])
    for key, values in stats["top_network_indicators"].items():
        if not values:
            continue
        rendered = ", ".join(f"`{row['value']}` ({row['count']})" for row in values[:10])
        lines.append(f"- {key}: {rendered}")
    lines.extend(["", "## Top High-Signal Samples", ""])
    for row in stats["top_high_signal_samples"][:25]:
        highlights = " | ".join(str(x) for x in row.get("highlights") or []) or "no highlights"
        lines.append(
            f"- `{row['batch']}` idx={row['idx']} md5=`{row['md5']}` "
            f"score={row['signal_score']} status={row['status']} "
            f"net={row['network_events']} drop={row['dropped_artifacts']} :: {highlights}"
        )
    lines.extend(["", "## Per Batch", ""])
    for row in stats["by_dir"]:
        lines.append(
            f"- `{row['name']}`: selected={row['selected']} completed={row['completed']} "
            f"network={row['network_samples']} behavior={row['behavior_signal_samples']} "
            f"handler_blockers={row['handler_blockers']} timeouts={row['timeouts']}"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--pattern", default="inthewild_*_diverse_*")
    parser.add_argument("--output-prefix", type=Path, default=None)
    parser.add_argument("--indicator-limit", type=int, default=50)
    args = parser.parse_args()

    stats = build_stats(args.root, args.pattern, args.indicator_limit)
    prefix = args.output_prefix or (args.root / "speakeasy_corpus_stats")
    prefix.parent.mkdir(parents=True, exist_ok=True)
    json_path = prefix.with_suffix(".json")
    md_path = prefix.with_suffix(".md")
    json_path.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    write_markdown(stats, md_path)
    print(json.dumps({"json": str(json_path), "markdown": str(md_path), "completed_total": stats["completed_total"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
