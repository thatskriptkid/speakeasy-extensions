#!/usr/bin/env python3
"""
Сводка по отчёту Speakeasy: компактный текст/JSON для LLM или triage.
Из большого JSON вытаскивает: уникальные API, счётчики, пути/сеть (если есть).

Использование:
  python host/speakeasy_summary.py speakeasy_report_sample.json
  python host/speakeasy_summary.py -j report.json   # только JSON сводка
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def extract_apis(report: dict) -> list[str]:
    apis = []
    for ep in report.get("entry_points") or []:
        for call in ep.get("apis") or []:
            name = call.get("api_name")
            if name:
                apis.append(name)
    return apis


def summarize(report_path: Path, max_apis: int = 200) -> dict:
    with open(report_path, encoding="utf-8", errors="replace") as f:
        report = json.load(f)
    apis = extract_apis(report)
    unique = sorted(set(apis))
    by_prefix: dict[str, int] = {}
    for a in apis:
        prefix = a.split(".")[0] if "." in a else "other"
        by_prefix[prefix] = by_prefix.get(prefix, 0) + 1
    summary = {
        "path": str(report_path),
        "binary": report.get("binary") or report.get("path", ""),
        "sha256": report.get("sha256", ""),
        "arch": report.get("arch", ""),
        "filetype": report.get("filetype", ""),
        "emulation_runtime_sec": report.get("emulation_total_runtime"),
        "timeout_triggered": report.get("timeout_triggered", False),
        "total_api_calls": len(apis),
        "unique_apis_count": len(unique),
        "api_calls_by_module": dict(sorted(by_prefix.items(), key=lambda x: -x[1])),
        "unique_apis_sample": unique[:max_apis],
    }
    if len(unique) > max_apis:
        summary["unique_apis_truncated"] = True
    return summary


def summary_to_text(s: dict) -> str:
    lines = [
        f"Binary: {s.get('binary', '')}",
        f"SHA256: {s.get('sha256', '')}",
        f"Arch: {s.get('arch', '')}  Type: {s.get('filetype', '')}",
        f"Runtime: {s.get('emulation_runtime_sec')}s  Timeout: {s.get('timeout_triggered', False)}",
        f"API calls: {s.get('total_api_calls', 0)} total, {s.get('unique_apis_count', 0)} unique",
        "",
        "By module:",
    ]
    for mod, count in (s.get("api_calls_by_module") or {}).items():
        lines.append(f"  {mod}: {count}")
    lines.append("")
    lines.append("Unique APIs (sample):")
    for a in (s.get("unique_apis_sample") or [])[:80]:
        lines.append(f"  {a}")
    if s.get("unique_apis_truncated"):
        lines.append("  ... (truncated)")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Speakeasy report summary for LLM/triage")
    parser.add_argument("report", type=Path, help="Path to speakeasy_report_*.json")
    parser.add_argument("-j", "--json-only", action="store_true", help="Output only JSON summary")
    parser.add_argument("--max-apis", type=int, default=200, help="Max unique APIs in sample (default 200)")
    args = parser.parse_args()
    if not args.report.exists():
        print(f"[-] Not found: {args.report}", file=sys.stderr)
        return 1
    s = summarize(args.report, max_apis=args.max_apis)
    if args.json_only:
        print(json.dumps(s, indent=2, ensure_ascii=False))
    else:
        print(summary_to_text(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
