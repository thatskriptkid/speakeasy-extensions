#!/usr/bin/env python3
"""Run Mandiant Speakeasy in Docker and preserve pipeline-compatible artifacts.

This intentionally replaces the old native-Python Speakeasy path. Keeping
Speakeasy in a container avoids polluting the project venv and sidesteps the
Apple Silicon/unicorn instability that made native runs unreliable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = "speakeasy-extensions:1.5.11"
DEFAULT_PLATFORM = "linux/amd64" if sys.platform == "darwin" else ""
MAX_ARTIFACT_STEM = 170
DEFAULT_MODULE_DIR_X64 = Path("modules/x64")
DEFAULT_MODULE_DIR_X86 = Path("modules/x86")


@dataclass(frozen=True)
class Profile:
    name: str
    timeout: int
    memory_trace: bool = False
    memory_dump: bool = False
    emulate_children: bool = False
    dropped_files: bool = True


PROFILES: dict[str, Profile] = {
    "fast": Profile("fast", timeout=300),
    "deep": Profile("deep", timeout=300, memory_trace=True, memory_dump=True),
    "children": Profile("children", timeout=300, emulate_children=True),
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _docker() -> str:
    docker = os.environ.get("SPEAKEASY_DOCKER_BIN") or shutil.which("docker")
    if not docker:
        raise RuntimeError("docker executable not found")
    return docker


def _run_quiet(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True)


def _image_exists(docker: str, image: str) -> bool:
    return _run_quiet([docker, "image", "inspect", image]).returncode == 0


def _build_image(docker: str, image: str, platform: str) -> None:
    dockerfile = PROJECT_ROOT / "Dockerfile"
    if not dockerfile.is_file():
        raise RuntimeError(f"Speakeasy Dockerfile not found: {dockerfile}")
    cmd = [docker, "build", "-t", image, "-f", str(dockerfile)]
    if platform:
        cmd += ["--platform", platform]
    cmd.append(str(PROJECT_ROOT))
    print(f"[*] Building Speakeasy Docker image: {' '.join(shlex.quote(x) for x in cmd)}", file=sys.stderr)
    subprocess.run(cmd, check=True)


def _container_path(path: Path, root: Path, mount: str) -> str:
    rel = path.resolve().relative_to(root.resolve())
    return str(Path(mount) / rel).replace("\\", "/")


def _summary(report_path: Path, summary_path: Path) -> None:
    try:
        from speakeasy_summary import summarize, summary_to_text

        data = summarize(report_path)
        summary_path.write_text(summary_to_text(data) + "\n", encoding="utf-8")
    except Exception as e:
        summary_path.write_text(f"Speakeasy summary failed: {e}\n", encoding="utf-8")


def _behavior(report_path: Path, behavior_path: Path, behavior_summary_path: Path) -> None:
    try:
        from speakeasy_behavior import build_behavior, behavior_to_text

        data = build_behavior(report_path)
        behavior_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        behavior_summary_path.write_text(behavior_to_text(data) + "\n", encoding="utf-8")
        network_path = behavior_path.with_name(behavior_path.name.replace("speakeasy_behavior_", "speakeasy_network_", 1))
        network_summary_path = behavior_summary_path.with_name(
            behavior_summary_path.name.replace("speakeasy_behavior_", "speakeasy_network_", 1)
        )
        network = {
            "schema": "speakeasy-extensions.speakeasy-network.v1",
            "source_report": str(report_path),
            "sample": data.get("sample") or {},
            "emulation": data.get("emulation") or {},
            "summary": {
                "network_intent": bool((data.get("summary") or {}).get("network_intent")),
                "category_counts": {"network": ((data.get("summary") or {}).get("category_counts") or {}).get("network", 0)},
            },
            "network": ((data.get("categories") or {}).get("network") or {}),
        }
        network_path.write_text(json.dumps(network, indent=2, ensure_ascii=False), encoding="utf-8")
        lines = [
            "Speakeasy offline network summary",
            f"Network intent: {network['summary']['network_intent']}",
        ]
        indicators = (network["network"].get("indicators") or {}) if isinstance(network.get("network"), dict) else {}
        for key in ("urls", "hosts", "domains", "ips", "resolved_ips", "endpoints", "emulated_endpoints"):
            values = indicators.get(key) or []
            if values:
                lines.append(f"{key}: " + ", ".join(str(v) for v in values[:20]))
        network_summary_path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    except Exception as e:
        behavior_path.write_text(
            json.dumps(
                {
                    "schema": "speakeasy-extensions.speakeasy-behavior.v1",
                    "source_report": str(report_path),
                    "error": f"Speakeasy behavior extraction failed: {e}",
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        behavior_summary_path.write_text(f"Speakeasy behavior extraction failed: {e}\n", encoding="utf-8")


def _metadata_path(report_dir: Path, stem: str) -> Path:
    return report_dir / f"speakeasy_metadata_{stem}.json"


def _artifact_stem(binary: Path) -> str:
    stem = binary.stem
    # macOS/APFS and many Linux filesystems cap a single filename component at
    # 255 bytes. InTheWild samples can have 240+ char family-label filenames;
    # adding speakeasy_report_/summary suffixes would exceed that cap. Keep
    # human context plus a stable hash so artifacts remain unique and mappable.
    if len(stem.encode("utf-8")) <= MAX_ARTIFACT_STEM:
        return stem
    digest = hashlib.sha256(stem.encode("utf-8", errors="replace")).hexdigest()[:16]
    prefix_budget = MAX_ARTIFACT_STEM - len(digest) - 1
    prefix = stem.encode("utf-8")[:prefix_budget].decode("utf-8", errors="ignore").rstrip("._-")
    return f"{prefix}_{digest}"


def _write_metadata(path: Path, meta: dict[str, Any]) -> None:
    path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")


def _container_name(binary: Path) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.-]+", "-", binary.stem).strip(".-").lower()
    safe = safe[:48] or "sample"
    digest = hashlib.sha256(f"{binary}:{time.time_ns()}".encode("utf-8")).hexdigest()[:12]
    return f"speakeasy-extensions-{safe}-{digest}"


def _profile_config(profile_name: str, explicit_config: Path | None) -> Path | None:
    if explicit_config:
        return explicit_config.expanduser().resolve()
    env_config = os.environ.get("SPEAKEASY_PROFILE_CONFIG", "").strip()
    if env_config:
        return Path(env_config).expanduser().resolve()
    config_dir = os.environ.get("SPEAKEASY_CONFIG_DIR", "").strip()
    if config_dir:
        config_root = Path(config_dir).expanduser()
        if not config_root.is_absolute():
            config_root = PROJECT_ROOT / config_root
    else:
        config_root = PROJECT_ROOT / "config"
    candidate = config_root.resolve() / f"{profile_name}.json"
    return candidate if candidate.is_file() else None


def _detect_pe_arch(path: Path) -> str:
    try:
        data = path.read_bytes()[:0x1000]
        if len(data) < 0x40 or data[:2] != b"MZ":
            return ""
        pe_off = int.from_bytes(data[0x3C:0x40], "little")
        if pe_off < 0 or pe_off + 6 > len(data):
            with path.open("rb") as f:
                f.seek(pe_off)
                sig_machine = f.read(6)
        else:
            sig_machine = data[pe_off:pe_off + 6]
        if sig_machine[:4] != b"PE\x00\x00":
            return ""
        machine = int.from_bytes(sig_machine[4:6], "little")
    except Exception:
        return ""
    return {
        0x014C: "x86",
        0x8664: "x64",
        0xAA64: "arm64",
    }.get(machine, "")


def _auto_module_dir(binary: Path, raw_arch: str = "") -> tuple[Path | None, str, str]:
    arch = (raw_arch or "").lower()
    if arch in {"amd64", "x86_64"}:
        arch = "x64"
    elif arch in {"i386", "i686", "win32"}:
        arch = "x86"
    if not arch:
        arch = _detect_pe_arch(binary)

    env_by_arch = {
        "x64": os.environ.get("SPEAKEASY_MODULE_DIR_X64", "").strip(),
        "x86": os.environ.get("SPEAKEASY_MODULE_DIR_X86", "").strip(),
    }
    defaults = {
        "x64": DEFAULT_MODULE_DIR_X64,
        "x86": DEFAULT_MODULE_DIR_X86,
    }
    if arch in env_by_arch and env_by_arch[arch]:
        return Path(env_by_arch[arch]).expanduser().resolve(), arch, f"env:SPEAKEASY_MODULE_DIR_{arch.upper()}"
    candidate = defaults.get(arch)
    if candidate and not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    if candidate and candidate.is_dir():
        return candidate.resolve(), arch, "default"
    return None, arch, ""


def entrypoint_docker_args(all_entrypoints: bool | None) -> list[str]:
    """Pass the patched Speakeasy CLI switch into the container. None keeps the image default."""

    if all_entrypoints is None:
        return []
    return ["-e", f"SPEAKEASY_ALL_ENTRYPOINTS={'1' if all_entrypoints else '0'}"]


def run(args: argparse.Namespace) -> int:
    binary = args.binary.expanduser().resolve()
    if not binary.is_file():
        print(f"[-] file not found: {binary}", file=sys.stderr)
        return 1

    report_dir = args.report_dir.expanduser().resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    # Docker userns-remap is not the host user. The output dir must be writable
    # by that mapped uid or Speakeasy cannot save the JSON report.
    try:
        os.chmod(report_dir, 0o777)
    except OSError:
        pass
    stem = binary.stem
    artifact_stem = _artifact_stem(binary)

    profile = PROFILES[args.profile]
    timeout = args.timeout or int(os.environ.get("SPEAKEASY_TIMEOUT", "0") or 0) or profile.timeout
    image = args.image or os.environ.get("SPEAKEASY_DOCKER_IMAGE", DEFAULT_IMAGE)
    platform = args.platform
    if platform is None:
        platform = os.environ.get("SPEAKEASY_DOCKER_PLATFORM", DEFAULT_PLATFORM)
    memory = args.memory or os.environ.get("SPEAKEASY_DOCKER_MEMORY", "2g")
    cpus = args.cpus or os.environ.get("SPEAKEASY_DOCKER_CPUS", "2")
    network = args.network or os.environ.get("SPEAKEASY_DOCKER_NETWORK", "none")
    if network and network != "none" and not _env_bool("SPEAKEASY_ALLOW_DOCKER_NETWORK", False):
        print(
            "[-] refusing to run Speakeasy with Docker network "
            f"{network!r}; set SPEAKEASY_ALLOW_DOCKER_NETWORK=1 only for an isolated lab network",
            file=sys.stderr,
        )
        return 1
    config_path = _profile_config(profile.name, args.config)
    module_dir_arg = args.module_dir
    module_dir_arch = ""
    module_dir_source = "none"
    if module_dir_arg:
        module_dir_source = "cli"
    elif os.environ.get("SPEAKEASY_MODULE_DIR"):
        module_dir_arg = Path(os.environ["SPEAKEASY_MODULE_DIR"])
        module_dir_source = "env:SPEAKEASY_MODULE_DIR"
    else:
        module_dir_arg, module_dir_arch, module_dir_source = _auto_module_dir(binary, args.arch if args.raw else "")

    report_path = report_dir / f"speakeasy_report_{artifact_stem}.json"
    summary_path = report_dir / f"speakeasy_report_{artifact_stem}_summary.txt"
    behavior_path = report_dir / f"speakeasy_behavior_{artifact_stem}.json"
    behavior_summary_path = report_dir / f"speakeasy_behavior_{artifact_stem}_summary.txt"
    network_path = report_dir / f"speakeasy_network_{artifact_stem}.json"
    network_summary_path = report_dir / f"speakeasy_network_{artifact_stem}_summary.txt"
    stdout_path = report_dir / f"speakeasy_{artifact_stem}.stdout.txt"
    stderr_path = report_dir / f"speakeasy_{artifact_stem}.stderr.txt"
    dropped_path = report_dir / f"speakeasy_dropped_{artifact_stem}.zip"
    memdump_path = report_dir / f"speakeasy_memory_{artifact_stem}.zip"
    metadata_path = _metadata_path(report_dir, artifact_stem)

    docker = _docker()
    if not _image_exists(docker, image):
        if args.no_auto_build or not _env_bool("SPEAKEASY_DOCKER_AUTO_BUILD", True):
            print(f"[-] Docker image not found: {image}", file=sys.stderr)
            return 1
        _build_image(docker, image, platform)

    input_root = binary.parent.resolve()
    out_root = report_dir.resolve()
    target_in_container = _container_path(binary, input_root, "/input")
    report_in_container = f"/out/{report_path.name}"
    dropped_in_container = f"/out/{dropped_path.name}"
    memdump_in_container = f"/out/{memdump_path.name}"

    speakeasy_cmd = [
        "speakeasy",
        "-t",
        target_in_container,
        "-o",
        report_in_container,
        "-q",
        str(timeout),
    ]

    if args.raw:
        speakeasy_cmd.append("-r")
        if args.arch:
            speakeasy_cmd += ["-a", args.arch]
        if args.raw_offset:
            speakeasy_cmd += ["--raw_offset", args.raw_offset]
    if args.argv:
        speakeasy_cmd += ["-p", *shlex.split(args.argv)]
    if config_path:
        if not config_path.is_file():
            print(f"[-] config not found: {config_path}", file=sys.stderr)
            return 1
        cfg_parent = config_path.parent
        speakeasy_cmd += ["-c", _container_path(config_path, cfg_parent, "/config")]
    if module_dir_arg:
        module_dir = module_dir_arg.expanduser().resolve()
        if not module_dir.is_dir():
            print(f"[-] module dir not found: {module_dir}", file=sys.stderr)
            return 1
        speakeasy_cmd += ["-l", "/modules"]

    memory_trace = _env_bool("SPEAKEASY_MEMORY_TRACE", profile.memory_trace)
    memory_dump = _env_bool("SPEAKEASY_MEMORY_DUMP", profile.memory_dump)
    emulate_children = _env_bool("SPEAKEASY_EMULATE_CHILDREN", profile.emulate_children)
    dropped_files = _env_bool("SPEAKEASY_DROPPED_FILES", profile.dropped_files)
    if args.dump_dir:
        memory_dump = True

    if memory_trace:
        speakeasy_cmd.append("-m")
    if memory_dump:
        speakeasy_cmd += ["-d", memdump_in_container]
    if dropped_files:
        speakeasy_cmd += ["-z", dropped_in_container]
    if emulate_children:
        speakeasy_cmd.append("-k")
    if args.extra_speakeasy_args:
        speakeasy_cmd += shlex.split(args.extra_speakeasy_args)

    container_name = _container_name(binary)
    docker_cmd = [docker, "run", "--rm", "--name", container_name]
    if platform:
        docker_cmd += ["--platform", platform]
    if network:
        docker_cmd += ["--network", network]
    if memory:
        docker_cmd += ["--memory", memory]
    if cpus:
        docker_cmd += ["--cpus", cpus]
    docker_cmd += [
        "--pids-limit",
        os.environ.get("SPEAKEASY_DOCKER_PIDS_LIMIT", "512"),
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "-v",
        f"{input_root}:/input:ro",
        "-v",
        f"{out_root}:/out:rw",
    ]
    if config_path:
        docker_cmd += ["-v", f"{config_path.parent}:/config:ro"]
    if module_dir_arg:
        docker_cmd += ["-v", f"{module_dir_arg.expanduser().resolve()}:/modules:ro"]
    extra_docker = os.environ.get("SPEAKEASY_DOCKER_EXTRA_ARGS", "").strip()
    if extra_docker:
        docker_cmd += shlex.split(extra_docker)
    all_entrypoints = getattr(args, "all_entrypoints", None)
    docker_cmd += entrypoint_docker_args(all_entrypoints)
    docker_cmd += [image, *speakeasy_cmd]

    meta: dict[str, Any] = {
        "schema": "speakeasy-extensions.speakeasy-docker.v1",
        "binary": str(binary),
        "sample_stem": stem,
        "artifact_stem": artifact_stem,
        "profile": profile.name,
        "timeout": timeout,
        "image": image,
        "platform": platform,
        "network": network,
        "config_path": str(config_path) if config_path else "",
        "module_dir": str(module_dir_arg.expanduser().resolve()) if module_dir_arg else "",
        "module_dir_arch": module_dir_arch,
        "module_dir_source": module_dir_source,
        "argv": args.argv,
        "all_entrypoints": all_entrypoints,
        "memory_trace": memory_trace,
        "memory_dump": memory_dump,
        "emulate_children": emulate_children,
        "dropped_files": dropped_files,
        "report_path": str(report_path),
        "summary_path": str(summary_path),
        "behavior_path": str(behavior_path),
        "behavior_summary_path": str(behavior_summary_path),
        "network_path": str(network_path),
        "network_summary_path": str(network_summary_path),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "dropped_files_path": str(dropped_path),
        "memory_dump_path": str(memdump_path),
        "container_name": container_name,
        "docker_command": docker_cmd,
        "started_at": time.time(),
    }
    _write_metadata(metadata_path, meta)

    print(f"[*] Speakeasy Docker profile={profile.name} timeout={timeout}s target={binary.name}", file=sys.stderr)
    t0 = time.time()
    exit_code = 1
    timed_out = False
    wall_timeout = timeout + int(os.environ.get("SPEAKEASY_DOCKER_TIMEOUT_GRACE", "20"))
    with stdout_path.open("w", encoding="utf-8", errors="replace") as so, stderr_path.open(
        "w", encoding="utf-8", errors="replace"
    ) as se:
        try:
            proc = subprocess.run(docker_cmd, stdout=so, stderr=se, timeout=wall_timeout)
            exit_code = proc.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = 124
            _run_quiet([docker, "kill", container_name])
            _run_quiet([docker, "rm", "-f", container_name])
    meta["exit_code"] = exit_code
    meta["timed_out"] = timed_out
    meta["wall_timeout_seconds"] = wall_timeout
    meta["duration_seconds"] = round(time.time() - t0, 3)
    meta["finished_at"] = time.time()
    meta["report_exists"] = report_path.is_file() and report_path.stat().st_size > 0
    meta["behavior_exists"] = behavior_path.is_file() and behavior_path.stat().st_size > 0
    meta["dropped_files_exists"] = dropped_path.is_file() and dropped_path.stat().st_size > 0
    meta["memory_dump_exists"] = memdump_path.is_file() and memdump_path.stat().st_size > 0
    meta["stdout_size"] = stdout_path.stat().st_size if stdout_path.is_file() else 0
    meta["stderr_size"] = stderr_path.stat().st_size if stderr_path.is_file() else 0
    _write_metadata(metadata_path, meta)

    if report_path.is_file() and report_path.stat().st_size > 0:
        _summary(report_path, summary_path)
        _behavior(report_path, behavior_path, behavior_summary_path)
        meta["behavior_exists"] = behavior_path.is_file() and behavior_path.stat().st_size > 0
        _write_metadata(metadata_path, meta)
        print(f"[+] Speakeasy report: {report_path}", file=sys.stderr)
        print(f"[+] Speakeasy behavior: {behavior_path}", file=sys.stderr)
        return 0 if exit_code == 0 else exit_code

    print(f"[-] Speakeasy report missing: {report_path}", file=sys.stderr)
    return exit_code or 1


def main() -> int:
    p = argparse.ArgumentParser(description="Run Mandiant Speakeasy via Docker")
    p.add_argument("binary", type=Path, help="PE/shellcode to emulate")
    p.add_argument("-o", "--report-dir", type=Path, default=Path.cwd())
    p.add_argument("--dump-dir", type=Path, default=None, help="compatibility alias; enables memory dump artifact")
    p.add_argument("--profile", choices=sorted(PROFILES), default=os.environ.get("SPEAKEASY_PROFILE", "fast"))
    p.add_argument("--timeout", type=int, default=0)
    p.add_argument("--image", default="")
    p.add_argument("--platform", default=None)
    p.add_argument("--memory", default="")
    p.add_argument("--cpus", default="")
    p.add_argument("--network", default="")
    p.add_argument("--config", type=Path, default=None, help="Speakeasy config JSON mounted read-only")
    p.add_argument("--module-dir", type=Path, default=None, help="directory of PE modules for Speakeasy -l")
    entrypoints = p.add_mutually_exclusive_group()
    entrypoints.add_argument(
        "--all-entrypoints",
        dest="all_entrypoints",
        action="store_const",
        const=True,
        help="emulate every PE export (DLL/SYS); default is the image policy",
    )
    entrypoints.add_argument(
        "--no-all-entrypoints",
        dest="all_entrypoints",
        action="store_const",
        const=False,
        help="emulate only DllMain, EXE entry, or DriverEntry",
    )
    p.set_defaults(all_entrypoints=None)
    p.add_argument("--raw", action="store_true")
    p.add_argument("--arch", default="")
    p.add_argument("--raw-offset", default="")
    p.add_argument("--argv", default="", help="argv string passed to Speakeasy -p")
    p.add_argument("--extra-speakeasy-args", default=os.environ.get("SPEAKEASY_EXTRA_ARGS", ""))
    p.add_argument("--no-auto-build", action="store_true")
    args = p.parse_args()
    if args.profile not in PROFILES:
        print(f"[-] unknown profile: {args.profile}", file=sys.stderr)
        return 2
    try:
        return run(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print(f"[-] Speakeasy Docker runner failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
