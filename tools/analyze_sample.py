#!/usr/bin/env python3
"""Fast EXE/DLL/SYS triage on top of the existing Speakeasy shellcode runner.

Shellcode stays on ``run_speakeasy_docker.py --raw``. This command classifies a
PE, emulates the right entry (EXE entry, DllMain, or DriverEntry), and writes
one report. DLL and SYS exports are listed statically; pass ``--all-exports``
to emulate them too.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


TOOLS = Path(__file__).resolve().parent
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import pe_static  # noqa: E402
import run_speakeasy_docker as runner  # noqa: E402


SCHEMA = "speakeasy-extensions.pe-triage.v1"
FAST_TIMEOUT = 60


def emulation_plan(kind: str, *, raw: bool, all_exports: bool) -> dict[str, Any]:
    if raw or kind == "shellcode":
        return {"raw": True, "all_entrypoints": None, "entry_mode": "shellcode"}
    mode = pe_static.entry_mode(kind, all_exports=all_exports)
    return {
        "raw": False,
        "all_entrypoints": bool(all_exports),
        "entry_mode": mode,
    }


def behavior_excerpt(behavior: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(behavior, dict):
        return {}
    summary = behavior.get("summary") or {}
    analysis = behavior.get("analysis") or {}
    emulation = behavior.get("emulation") or {}
    counts: dict[str, int] = {}
    for name, bucket in (behavior.get("categories") or {}).items():
        if isinstance(bucket, dict):
            counts[str(name)] = int(bucket.get("count") or 0)
    candidates = []
    for item in (analysis.get("c2_candidates") or [])[:8]:
        if isinstance(item, dict):
            candidates.append(
                {
                    "type": item.get("type"),
                    "value": item.get("value"),
                    "confidence": item.get("confidence"),
                }
            )
    return {
        "api_calls": emulation.get("api_calls_total"),
        "runtime_seconds": emulation.get("runtime_seconds"),
        "error_count": emulation.get("error_count"),
        "highlights": [str(item) for item in (summary.get("highlights") or [])[:12]],
        "c2_candidates": candidates,
        "category_counts": counts,
    }


def limitations(kind: str, entry_mode: str, dotnet: bool) -> list[str]:
    lines = [
        "Эмуляция идёт в Docker без сети хоста. DNS и сокеты — синтетические ответы Speakeasy, не живой C2.",
        "Ранняя остановка не доказывает, что файл безобиден: не хватает API-хука, распаковщика или контекста процесса.",
        "Это не восстановление исходного процесса, PEB и внедрённой памяти.",
    ]
    if dotnet:
        lines.append("Speakeasy 1.5.11 не эмулирует .NET. Отчёт содержит только статику PE.")
    if kind == "dll" and entry_mode == "DllMain":
        lines.append("Быстрый режим DLL исполняет только DllMain. Экспорты перечислены статически; --all-exports запускает их все и может быть долгим.")
    if kind == "sys":
        lines.append("SYS идёт через kernel-эмулятор Speakeasy (DriverEntry). Отсутствующий ntoskrnl-хук останавливает драйвер рано.")
    if kind == "shellcode":
        lines.append("Shellcode эмулируется как raw-блоб. Архитектуру нужно задать явно, если она не указана.")
    return lines


def build_report(
    *,
    sample_path: Path,
    sha256: str,
    size: int,
    static: dict[str, Any] | None,
    plan: dict[str, Any],
    profile: str,
    timeout: int,
    exit_code: int | None,
    behavior: dict[str, Any] | None,
    behavior_path: str = "",
    emulation_error: str = "",
) -> dict[str, Any]:
    kind = "shellcode" if plan.get("raw") else str((static or {}).get("kind") or "unknown")
    dotnet = bool((static or {}).get("dotnet"))
    if dotnet:
        status = "unsupported"
    elif static is None and not plan.get("raw"):
        status = "not_pe"
    elif behavior:
        status = "completed" if exit_code == 0 else "limited"
    else:
        status = "emulation_failed"
    return {
        "schema": SCHEMA,
        "status": status,
        "sample": {
            "path": str(sample_path),
            "name": sample_path.name,
            "sha256": sha256,
            "size": size,
            "kind": kind,
            "arch": (static or {}).get("arch") or "",
            "subsystem": (static or {}).get("subsystem") or "",
            "magic": (static or {}).get("magic") or "",
            "image_base": (static or {}).get("image_base"),
            "entry_rva": (static or {}).get("entry_rva"),
            "timestamp": (static or {}).get("timestamp"),
            "dotnet": dotnet,
            "sections": (static or {}).get("sections") or [],
            "imports": (static or {}).get("imports") or [],
            "exports": (static or {}).get("exports") or [],
            "export_count_truncated": bool((static or {}).get("export_count_truncated")),
        },
        "emulation": {
            "profile": profile,
            "timeout_seconds": timeout,
            "entry_mode": plan.get("entry_mode") or "",
            "all_entrypoints": plan.get("all_entrypoints"),
            "exit_code": exit_code,
            "error": emulation_error,
            "behavior_path": behavior_path,
        },
        "behavior": behavior_excerpt(behavior),
        "limitations": limitations(kind, str(plan.get("entry_mode") or ""), dotnet),
    }


def report_to_markdown(report: dict[str, Any]) -> str:
    sample = report.get("sample") or {}
    emulation = report.get("emulation") or {}
    behavior = report.get("behavior") or {}
    lines = [
        f"# Быстрый разбор: {sample.get('name') or 'sample'}",
        "",
        f"- Статус: {report.get('status')}",
        f"- Тип: {sample.get('kind')} ({sample.get('arch') or 'arch ?'}, {sample.get('subsystem') or 'subsystem ?'})",
        f"- SHA256: {sample.get('sha256')}",
        f"- Размер: {sample.get('size')} байт",
        f"- Точка входа: {emulation.get('entry_mode')} RVA {sample.get('entry_rva')}",
        f"- Профиль: {emulation.get('profile')}, таймаут {emulation.get('timeout_seconds')} с",
        "",
        "## Статика",
        "",
    ]
    sections = sample.get("sections") or []
    if sections:
        lines.append("Секции:")
        for item in sections[:24]:
            lines.append(
                f"- {item.get('name') or '?'} VA 0x{int(item.get('virtual_address') or 0):x} "
                f"vsize 0x{int(item.get('virtual_size') or 0):x}"
            )
        lines.append("")
    imports = sample.get("imports") or []
    if imports:
        lines.append("Импорты:")
        for item in imports[:32]:
            names = ", ".join(str(name) for name in (item.get("imports") or [])[:12])
            extra = ""
            rest = len(item.get("imports") or []) - 12
            if rest > 0:
                extra = f" (+{rest})"
            lines.append(f"- {item.get('dll')}: {names}{extra}")
        lines.append("")
    exports = sample.get("exports") or []
    if exports:
        shown = ", ".join(str(name) for name in exports[:40])
        suffix = " …" if sample.get("export_count_truncated") or len(exports) > 40 else ""
        lines.append(f"Экспорты: {shown}{suffix}")
        lines.append("")
    if not sections and not imports and not exports:
        lines.append("Статических секций, импортов и экспортов нет (shellcode или не-PE).")
        lines.append("")

    lines.extend(["## Эмуляция", ""])
    if emulation.get("error"):
        lines.append(f"Ошибка: {emulation.get('error')}")
    else:
        lines.append(f"Код выхода контейнера: {emulation.get('exit_code')}")
    if emulation.get("behavior_path"):
        lines.append(f"Полное поведение: {emulation.get('behavior_path')}")
    lines.append("")

    lines.extend(["## Поведение", ""])
    if not behavior:
        lines.append("Поведенческий отчёт не получен.")
    else:
        lines.append(
            f"API: {behavior.get('api_calls')}, runtime: {behavior.get('runtime_seconds')} с, "
            f"ошибки: {behavior.get('error_count')}"
        )
        counts = behavior.get("category_counts") or {}
        if counts:
            lines.append("Категории: " + ", ".join(f"{key}={value}" for key, value in counts.items()))
        for item in behavior.get("highlights") or []:
            lines.append(f"- {item}")
        for item in behavior.get("c2_candidates") or []:
            lines.append(f"- C2 {item.get('confidence')}: {item.get('type')} {item.get('value')}")
    lines.extend(["", "## Ограничения", ""])
    for item in report.get("limitations") or []:
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_report(report_dir: Path, report: dict[str, Any]) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / "triage_report.json"
    md_path = report_dir / "triage_report.md"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(report_to_markdown(report), encoding="utf-8")
    return json_path, md_path


def analyze(args: argparse.Namespace) -> int:
    sample = args.sample.expanduser().resolve()
    if not sample.is_file():
        print(f"[-] file not found: {sample}", file=sys.stderr)
        return 1
    report_dir = (args.report_dir or Path("out") / sample.stem).expanduser().resolve()
    blob = sample.read_bytes()
    static = pe_static.parse_pe(blob, sample.name)
    raw = bool(args.raw or (static is None and args.arch))
    if static is None and not raw:
        print("[-] not a PE. For shellcode pass --raw --arch x86|x64", file=sys.stderr)
        return 2
    if raw and not args.arch and static is None:
        print("[-] shellcode needs --arch x86 or x64", file=sys.stderr)
        return 2
    kind = "shellcode" if static is None else str(static["kind"])
    plan = emulation_plan(kind, raw=raw, all_exports=bool(args.all_exports))
    if raw:
        plan["raw"] = True
        plan["entry_mode"] = "shellcode"
        plan["all_entrypoints"] = None
    timeout = args.timeout or FAST_TIMEOUT
    exit_code: int | None = None
    error = ""
    behavior = None
    behavior_path = ""
    if static and static.get("dotnet"):
        error = "Speakeasy does not emulate .NET assemblies"
    else:
        namespace = argparse.Namespace(
            binary=sample,
            report_dir=report_dir,
            dump_dir=None,
            profile=args.profile,
            timeout=timeout,
            image=args.image,
            platform=args.platform,
            memory=args.memory,
            cpus=args.cpus,
            network="",
            config=args.config,
            module_dir=args.module_dir,
            raw=bool(plan["raw"]),
            arch=args.arch or str((static or {}).get("arch") or ""),
            raw_offset=args.raw_offset,
            argv=args.argv,
            extra_speakeasy_args=args.extra_speakeasy_args,
            no_auto_build=args.no_auto_build,
            all_entrypoints=plan["all_entrypoints"],
        )
        try:
            exit_code = runner.run(namespace)
        except Exception as exc:
            error = str(exc)
            exit_code = 1
        stem = runner._artifact_stem(sample)
        candidate = report_dir / f"speakeasy_behavior_{stem}.json"
        if candidate.is_file():
            behavior = _load_json(candidate)
            behavior_path = str(candidate)
        if not error and not behavior:
            error = "speakeasy produced no behavior report"
        elif behavior:
            error = ""
    report = build_report(
        sample_path=sample,
        sha256=pe_static.sha256_file(sample),
        size=sample.stat().st_size,
        static=static,
        plan=plan,
        profile=args.profile,
        timeout=timeout,
        exit_code=exit_code,
        behavior=behavior,
        behavior_path=behavior_path,
        emulation_error=error,
    )
    json_path, md_path = write_report(report_dir, report)
    print(f"[+] triage report: {md_path}", file=sys.stderr)
    print(f"[+] triage json: {json_path}", file=sys.stderr)
    if report["status"] == "completed":
        return 0
    if report["status"] == "limited":
        return exit_code or 1
    if report["status"] == "unsupported":
        return 3
    return exit_code or 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fast Speakeasy triage for EXE, DLL, and SYS (shellcode via --raw)")
    parser.add_argument("sample", type=Path)
    parser.add_argument("-o", "--report-dir", type=Path, default=None)
    parser.add_argument("--profile", choices=sorted(runner.PROFILES), default="fast")
    parser.add_argument("--timeout", type=int, default=0, help=f"seconds (default {FAST_TIMEOUT})")
    parser.add_argument("--all-exports", action="store_true", help="also emulate DLL/SYS exports; default is DllMain or DriverEntry only")
    parser.add_argument("--raw", action="store_true", help="force the existing shellcode path")
    parser.add_argument("--arch", default="", help="x86 or x64; required for shellcode")
    parser.add_argument("--raw-offset", default="")
    parser.add_argument("--argv", default="")
    parser.add_argument("--config", type=Path, default=None)
    parser.add_argument("--module-dir", type=Path, default=None)
    parser.add_argument("--image", default="")
    parser.add_argument("--platform", default=None)
    parser.add_argument("--memory", default="")
    parser.add_argument("--cpus", default="")
    parser.add_argument("--extra-speakeasy-args", default="")
    parser.add_argument("--no-auto-build", action="store_true")
    args = parser.parse_args(argv)
    try:
        return analyze(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
