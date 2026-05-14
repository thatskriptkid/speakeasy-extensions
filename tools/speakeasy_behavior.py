#!/usr/bin/env python3
"""High-signal behavioral extraction from a Mandiant Speakeasy JSON report.

Speakeasy reports are useful, but raw API traces are noisy and can contain large
base64 write buffers. This module keeps the facts an analyst wants first:
network intent, file/registry/service/process activity, crypto, anti-analysis,
and dropped artifacts.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCHEMA = "speakeasy-extensions.speakeasy-behavior.v1"
CATEGORY_ORDER = (
    "network",
    "files",
    "registry",
    "services",
    "process_injection",
    "crypto",
    "anti_analysis",
    "dropped_artifacts",
)
CATEGORY_LABELS = {
    "network": "network",
    "files": "files",
    "registry": "registry",
    "services": "services",
    "process_injection": "process/injection",
    "crypto": "crypto",
    "anti_analysis": "anti-analysis",
    "dropped_artifacts": "dropped artifacts",
}

RE_IPV4 = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\."
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b"
)
RE_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)
RE_ENDPOINT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b")
PE_EXTENSIONS = {".exe", ".dll", ".scr", ".sys", ".ocx", ".cpl", ".drv"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".lnk"}
PERSISTENCE_REGISTRY_PATTERNS = (
    "\\run",
    "\\runonce",
    "\\services\\",
    "\\winlogon",
    "\\image file execution options",
    "\\policies\\explorer\\run",
    "\\currentversion\\explorer\\startupapproved",
)
LOLBIN_NAMES = (
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
)


NETWORK_FUNCS = {
    "wsastartup", "socket", "connect", "bind", "listen", "accept", "send", "sendto",
    "recv", "recvfrom", "gethostbyname", "getaddrinfo", "inet_addr", "inet_ntoa",
    "dnsquery_a", "dnsquery_w", "dnsqueryex", "urldownloadtofilea", "urldownloadtofilew",
    "internetopen", "internetopena", "internetopenw", "internetconnecta",
    "internetconnectw", "httpopenrequesta", "httpopenrequestw", "httpsendrequesta",
    "httpsendrequestw", "internetreadfile", "internetwritefile", "winhttpopen",
    "winhttpconnect", "winhttpopenrequest", "winhttpsendrequest", "winhttpreceiveresponse",
    "winhttpreaddata", "winhttpwritedata",
}
NETWORK_API_LABEL_PREFIXES = {
    "wininet", "winhttp", "winsock", "wsock32", "ws2_32", "dnsapi", "urlmon",
}
FILE_FUNCS = {
    "createfilea", "createfilew", "writefile", "readfile", "copyfilea", "copyfilew",
    "movefilea", "movefilew", "movefileexa", "movefileexw", "deletefilea", "deletefilew",
    "createdirectorya", "createdirectoryw", "removedirectorya", "removedirectoryw",
    "setfileattributesa", "setfileattributesw", "findfirstfilea", "findfirstfilew",
    "findnextfilea", "findnextfilew",
}
SERVICE_FUNCS = {
    "openscmanagera", "openscmanagerw", "createservicea", "createservicew",
    "openservicea", "openservicew", "startservicea", "startservicew",
    "controlservice", "deleteservice", "changeserviceconfiga", "changeserviceconfigw",
    "queryserviceconfiga", "queryserviceconfigw",
}
PROCESS_FUNCS = {
    "createprocessa", "createprocessw", "winexec", "shellexecutea", "shellexecutew",
    "openprocess", "virtualalloc", "virtualallocex", "virtualprotect", "virtualprotectex",
    "writeprocessmemory", "readprocessmemory", "createremotethread", "createthread",
    "queueuserapc", "ntqueueapcthread", "ntcreatethreadex", "resumethread",
    "suspendthread", "setwindowshookexa", "setwindowshookexw", "loadlibrarya",
    "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
}
CRYPTO_FUNCS = {
    "cryptacquirecontexta", "cryptacquirecontextw", "cryptcreatehash", "crypthashdata",
    "cryptderivekey", "cryptgenkey", "cryptdecrypt", "cryptencrypt", "cryptimportkey",
    "cryptexportkey", "cryptstringtobinarya", "cryptstringtobinaryw",
    "bcryptopenalgorithmprovider", "bcryptsetproperty", "bcryptcreatehash",
    "bcrypthashdata", "bcryptfinishhash", "bcryptgeneratekeypair", "bcryptimportkey",
    "bcryptdecrypt", "bcryptencrypt", "ncryptopenstorageprovider", "ncryptopenkey",
    "ncryptdecrypt", "ncryptencrypt",
}
ANTI_ANALYSIS_FUNCS = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa",
    "outputdebugstringw", "ntqueryinformationprocess", "gettickcount",
    "gettickcount64", "queryperformancecounter", "queryperformancefrequency",
    "sleep", "sleepex", "ntdelayexecution", "zwdelayexecution",
    "getsystemtime", "getlocaltime", "getkeyboardlayout",
    "getkeyboardtype", "getuserdefaultlangid", "getuserdefaultuilanguage",
    "getlocaleinfoa", "getlocaleinfow", "getsystemmetrics", "enumdisplaymonitors",
    "systemparametersinfoa", "systemparametersinfow", "getcomputernamea",
    "getcomputernamew", "getusernamea", "getusernamew", "getvolumeinformationa",
    "getvolumeinformationw", "globalmemorystatusex", "getsysteminfo",
    "getnativesysteminfo", "createhelp32snapshot", "createtoolhelp32snapshot",
    "process32first", "process32firstw", "process32next", "process32nextw",
    "module32first", "module32firstw", "module32next", "module32nextw",
    "getadaptersinfo", "getadapteraddresses",
}


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="replace"))


def _shorten(value: Any, limit: int = 240) -> Any:
    if not isinstance(value, str):
        return value
    value = value.replace("\x00", "")
    if len(value) <= limit:
        return value
    return value[:limit] + f"... <truncated {len(value) - limit} chars>"


def _api_parts(api_name: str) -> tuple[str, str]:
    if "." in api_name:
        module, func = api_name.rsplit(".", 1)
    else:
        module, func = "", api_name
    return module.lower(), func.lower()


def _api_event(
    category: str,
    call: dict[str, Any],
    ep_index: int,
    seq: int,
    description: str,
    severity: str = "medium",
    tags: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    api_name = str(call.get("api_name") or "")
    module, func = _api_parts(api_name)
    event: dict[str, Any] = {
        "source": "api",
        "category": category,
        "severity": severity,
        "entry_point": ep_index,
        "sequence": seq,
        "pc": call.get("pc"),
        "api": api_name,
        "module": module,
        "function": func,
        "description": description,
        "args": [_shorten(a, 180) for a in (call.get("args") or [])],
        "ret_val": call.get("ret_val"),
    }
    if tags:
        event["tags"] = sorted(set(tags))
    for k, v in extra.items():
        if v not in (None, "", [], {}):
            event[k] = v
    return event


def _side_event(
    category: str,
    source: str,
    ep_index: int,
    description: str,
    severity: str = "medium",
    tags: list[str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "source": source,
        "category": category,
        "severity": severity,
        "entry_point": ep_index,
        "description": description,
    }
    if tags:
        event["tags"] = sorted(set(tags))
    for k, v in extra.items():
        if v not in (None, "", [], {}):
            event[k] = v
    return event


def _path_ext(path: str) -> str:
    name = path.replace("/", "\\").rsplit("\\", 1)[-1]
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def _path_suspicious_tags(path: str) -> list[str]:
    low = path.lower()
    tags: list[str] = []
    ext = _path_ext(path)
    if ext in PE_EXTENSIONS:
        tags.append("pe_extension")
    if ext in SCRIPT_EXTENSIONS:
        tags.append("script_extension")
    if "\\appdata\\" in low or "\\temp\\" in low:
        tags.append("user_writable_location")
    if "\\windows\\" in low or "\\program files\\" in low:
        tags.append("system_location")
    if any(name in low for name in LOLBIN_NAMES):
        tags.append("lolbin_name")
    return tags


def _is_pe_like_value(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    low = value.lower()
    if "4d5a" in low[:256] or "(4d5a" in low:
        return True
    compact = value.strip()
    if compact.startswith(("TVq", "TVp")):
        return True
    if len(compact) >= 8:
        try:
            decoded = base64.b64decode(compact[:4096], validate=False)
            if decoded.startswith(b"MZ"):
                return True
        except (binascii.Error, ValueError):
            return False
    return False


def _sanitize_file_event(raw: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key in ("event", "path", "size", "buffer", "open_flags", "access_flags"):
        if key in raw:
            out[key] = _shorten(raw.get(key), 260)
    data = raw.get("data")
    if isinstance(data, str):
        out["data_len"] = len(data)
        out["data_preview"] = _shorten(data, 120)
        if _is_pe_like_value(data):
            out["pe_like_data"] = True
    path = str(raw.get("path") or "")
    if path:
        tags = _path_suspicious_tags(path)
        if tags:
            out["tags"] = tags
    return out


def _publicish_ip(ip: str) -> bool:
    bare = ip.split(":", 1)[0]
    parts = bare.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b, c, d = (int(x) for x in parts)
    except ValueError:
        return False
    if not all(0 <= x <= 255 for x in (a, b, c, d)):
        return False
    if a in {0, 10, 127, 169, 224, 255}:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if bare == "255.255.255.255":
        return False
    return True


def _extract_indicators(values: list[Any]) -> dict[str, list[str]]:
    text = "\n".join(str(v) for v in values if v not in (None, ""))
    urls = sorted(set(m.group(0).rstrip(".,);]\"'") for m in RE_URL.finditer(text)))
    endpoints = sorted(set(m.group(0) for m in RE_ENDPOINT.finditer(text) if _publicish_ip(m.group(0))))
    ips = sorted(set(ip.split(":", 1)[0] for ip in RE_IPV4.findall(text) if _publicish_ip(ip)))
    domains = sorted(
        set(
            d.lower().rstrip(".")
            for d in RE_DOMAIN.findall(text)
            if d.lower() not in {"tcp.http", "tcp.https", "udp.dns"}
            and not _looks_like_api_label(d)
            and not d.lower().endswith((
                ".dll", ".exe", ".tmp", ".log", ".dat", ".bin", ".pdb",
                ".zip", ".rar", ".7z", ".cab", ".msi", ".php", ".asp", ".aspx",
            ))
            and not d.split(".", 1)[0].isdigit()
        )
    )
    return {"urls": urls, "endpoints": endpoints, "ips": ips, "domains": domains}


def _looks_like_api_label(value: str) -> bool:
    low = (value or "").lower().strip(".")
    parts = low.split(".")
    if len(parts) != 2:
        return False
    module, func = parts
    return module in NETWORK_API_LABEL_PREFIXES and func in NETWORK_FUNCS


def _add_unique(bucket: defaultdict[str, set[str]], key: str, values: list[str] | set[str]) -> None:
    for value in values:
        if value:
            bucket[key].add(value)


def _registry_key_from_args(args: list[Any]) -> str:
    if not args:
        return ""
    root = str(args[0])
    sub = str(args[1]) if len(args) > 1 else ""
    if root.startswith("HKEY_") and sub and not sub.startswith("0x"):
        return root.rstrip("\\") + "\\" + sub.lstrip("\\")
    if root.startswith("HKEY_"):
        return root
    return sub if sub and not sub.startswith("0x") else root


def _registry_tags(path: str) -> list[str]:
    low = path.lower()
    tags = []
    if any(token in low for token in PERSISTENCE_REGISTRY_PATTERNS):
        tags.append("persistence_candidate")
    if "\\security center" in low or "\\windows defender" in low:
        tags.append("security_tool_config")
    return tags


def _service_name(func: str, args: list[Any]) -> str:
    if func.startswith("openservice") and len(args) > 1:
        return str(args[1])
    if func.startswith("createservice") and len(args) > 1:
        return str(args[1])
    if func.startswith("startservice") and args:
        return str(args[0])
    return ""


def _crypto_algorithms(args: list[Any]) -> list[str]:
    text = " ".join(str(a) for a in args)
    algs = []
    for alg in ("AES", "RC4", "RSA", "SHA512", "SHA384", "SHA256", "SHA1", "MD5", "CBC", "GCM", "DES", "3DES"):
        if re.search(rf"\b{re.escape(alg)}\b", text, re.IGNORECASE):
            algs.append(alg.upper())
    return sorted(set(algs))


def _anti_tags(func: str) -> list[str]:
    tags: list[str] = []
    if "debug" in func or func == "ntqueryinformationprocess":
        tags.append("debugger_check")
    if func in {
        "gettickcount", "gettickcount64", "queryperformancecounter", "sleep",
        "sleepex", "ntdelayexecution", "zwdelayexecution",
    }:
        tags.append("timing_check")
    if "keyboard" in func or "locale" in func or "lang" in func:
        tags.append("locale_keyboard_check")
    if "systemmetrics" in func or "display" in func or "monitor" in func:
        tags.append("display_check")
    if "computername" in func or "username" in func or "volumeinformation" in func or "adapter" in func:
        tags.append("host_fingerprint")
    if "process32" in func or "module32" in func or "toolhelp32" in func:
        tags.append("process_environment_enum")
    return tags or ["environment_check"]


def _severity_for_file_event(event_name: str, path: str, pe_like: bool = False) -> str:
    if pe_like:
        return "high"
    low_event = event_name.lower()
    tags = _path_suspicious_tags(path)
    if low_event in {"write", "create"} and ("pe_extension" in tags or "script_extension" in tags):
        return "high"
    if low_event in {"write", "create", "delete", "move", "copy"}:
        return "medium"
    return "low"


def _dedupe_events(events: list[dict[str, Any]], max_events: int) -> tuple[list[dict[str, Any]], int]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    omitted = 0
    severity_rank = {"high": 0, "medium": 1, "low": 2}
    sorted_events = sorted(
        events,
        key=lambda e: (
            severity_rank.get(str(e.get("severity")), 3),
            int(e.get("sequence") or 0),
            str(e.get("description") or ""),
        ),
    )
    for event in sorted_events:
        key = json.dumps(
            {
                "source": event.get("source"),
                "api": event.get("api"),
                "description": event.get("description"),
                "path": event.get("path"),
                "key_path": event.get("key_path"),
                "service_name": event.get("service_name"),
                "endpoint": event.get("endpoint"),
                "host": event.get("host"),
                "url": event.get("url"),
                "sha256": event.get("sha256"),
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        if key in seen:
            omitted += 1
            continue
        seen.add(key)
        if len(out) < max_events:
            out.append(event)
        else:
            omitted += 1
    out.sort(key=lambda e: int(e.get("sequence") or 0))
    return out, omitted


def _category_bucket() -> dict[str, Any]:
    return {
        "label": "",
        "count": 0,
        "events": [],
        "indicators": {},
        "notes": [],
    }


def build_behavior(report_path: Path, max_events_per_category: int = 200) -> dict[str, Any]:
    report = _load_json(report_path)
    categories = {name: _category_bucket() for name in CATEGORY_ORDER}
    for name, bucket in categories.items():
        bucket["label"] = CATEGORY_LABELS[name]

    all_events: dict[str, list[dict[str, Any]]] = {name: [] for name in CATEGORY_ORDER}
    indicators: dict[str, defaultdict[str, set[str]]] = {
        name: defaultdict(set) for name in CATEGORY_ORDER
    }
    api_counts = Counter()
    api_module_counts = Counter()
    handle_to_path: dict[str, str] = {}
    wininet_connect: dict[str, dict[str, Any]] = {}
    wininet_request: dict[str, dict[str, Any]] = {}
    registry_handles: dict[str, str] = {}
    sequence = 0

    entry_points = report.get("entry_points") or []
    for ep_index, ep in enumerate(entry_points):
        for raw in ep.get("file_access") or []:
            path = str(raw.get("path") or "")
            event_name = str(raw.get("event") or "file")
            pe_like = _is_pe_like_value(raw.get("data"))
            sanitized = _sanitize_file_event(raw)
            sanitized_tags = list(sanitized.pop("tags", []) or [])
            description = f"{event_name} {path}".strip()
            event = _side_event(
                "files",
                "file_access",
                ep_index,
                description,
                _severity_for_file_event(event_name, path, pe_like),
                sanitized_tags,
                **sanitized,
            )
            all_events["files"].append(event)
            if path:
                indicators["files"]["paths"].add(path)
                if event_name.lower() in {"write", "create"}:
                    indicators["files"]["write_paths"].add(path)
            if pe_like and path:
                indicators["dropped_artifacts"]["pe_like_paths"].add(path)

        for raw in ep.get("registry_access") or []:
            path = str(raw.get("path") or "")
            event_name = str(raw.get("event") or "registry")
            handle = str(raw.get("handle") or "")
            if handle and path:
                registry_handles[handle] = path
            tags = _registry_tags(path)
            event = _side_event(
                "registry",
                "registry_access",
                ep_index,
                f"{event_name} {path}".strip(),
                "high" if "persistence_candidate" in tags else "medium",
                tags,
                event=event_name,
                key_path=path,
                handle=handle,
            )
            all_events["registry"].append(event)
            if path:
                indicators["registry"]["keys"].add(path)
                if "persistence_candidate" in tags:
                    indicators["registry"]["persistence_candidates"].add(path)

        for raw in ep.get("process_events") or []:
            event_name = str(raw.get("event") or "process")
            path = str(raw.get("path") or "")
            cmdline = str(raw.get("cmdline") or "")
            tags = []
            if event_name == "mem_write":
                tags.append("memory_write")
            if any(x in (path + " " + cmdline).lower() for x in LOLBIN_NAMES):
                tags.append("lolbin_execution")
            event = _side_event(
                "process_injection",
                "process_events",
                ep_index,
                f"{event_name} {path or cmdline}".strip(),
                "high" if event_name == "mem_write" else "medium",
                tags,
                event=event_name,
                pid=raw.get("pid"),
                path=_shorten(path),
                cmdline=_shorten(cmdline),
                base=raw.get("base"),
                size=raw.get("size"),
            )
            all_events["process_injection"].append(event)
            if path:
                indicators["process_injection"]["process_paths"].add(path)
            if cmdline:
                indicators["process_injection"]["cmdlines"].add(cmdline)

        for raw in ep.get("dynamic_code_segments") or []:
            tag = str(raw.get("tag") or "")
            event = _side_event(
                "process_injection",
                "dynamic_code_segments",
                ep_index,
                f"dynamic code segment {tag}".strip(),
                "high",
                ["dynamic_code", "emitted_or_executable_memory"],
                tag=tag,
                base=raw.get("base"),
                size=raw.get("size"),
            )
            all_events["process_injection"].append(event)

        for raw in ep.get("dropped_files") or []:
            path = str(raw.get("path") or "")
            size = int(raw.get("size") or 0)
            sha256 = str(raw.get("sha256") or "")
            tags = _path_suspicious_tags(path)
            pe_like = _path_ext(path) in PE_EXTENSIONS or path in indicators["dropped_artifacts"]["pe_like_paths"]
            if pe_like:
                tags.append("pe_like")
            event = _side_event(
                "dropped_artifacts",
                "dropped_files",
                ep_index,
                f"dropped {path}".strip(),
                "high" if pe_like or tags else "medium",
                tags,
                path=path,
                size=size,
                sha256=sha256,
                pe_like=pe_like,
            )
            all_events["dropped_artifacts"].append(event)
            if path:
                indicators["dropped_artifacts"]["paths"].add(path)
            if sha256:
                indicators["dropped_artifacts"]["sha256"].add(sha256)
            if pe_like and path:
                indicators["dropped_artifacts"]["pe_like_paths"].add(path)

        network_events = ep.get("network_events") or {}
        for raw in network_events.get("dns") or []:
            sequence += 1
            query = str(raw.get("query") or "")
            response = str(raw.get("response") or "")
            values = [query, response]
            inds = _extract_indicators(values)
            _add_unique(indicators["network"], "domains", inds["domains"])
            _add_unique(indicators["network"], "ips", inds["ips"])
            _add_unique(indicators["network"], "urls", inds["urls"])
            _add_unique(indicators["network"], "endpoints", inds["endpoints"])
            if query:
                indicators["network"]["hosts"].add(query.rstrip(".").lower())
            for ip in RE_IPV4.findall(response):
                indicators["network"]["resolved_ips"].add(ip.split(":", 1)[0])
            event = _side_event(
                "network",
                "network_events.dns",
                ep_index,
                f"DNS query {query} -> {response or '<no response>'}".strip(),
                "medium",
                ["offline_emulation", "controlled_dns"],
                sequence=sequence,
                query=query,
                response=response,
            )
            all_events["network"].append(event)

        for raw in network_events.get("traffic") or []:
            sequence += 1
            server = str(raw.get("server") or raw.get("host") or "")
            port = str(raw.get("port") or "")
            proto = str(raw.get("proto") or raw.get("protocol") or "")
            method = str(raw.get("method") or raw.get("verb") or raw.get("type") or "")
            path = str(raw.get("path") or raw.get("uri") or "")
            headers = raw.get("headers")
            data = raw.get("data") or raw.get("body") or raw.get("buffer") or ""
            endpoint = f"{server}:{port}" if server and port else ""
            url = ""
            if server and path:
                scheme = "https" if port == "443" or "https" in proto.lower() else "http"
                url = path if path.lower().startswith(("http://", "https://")) else f"{scheme}://{server}{path}"
            values = [server, port, proto, method, path, headers, data, url]
            inds = _extract_indicators(values)
            _add_unique(indicators["network"], "domains", inds["domains"])
            _add_unique(indicators["network"], "ips", inds["ips"])
            _add_unique(indicators["network"], "urls", inds["urls"])
            _add_unique(indicators["network"], "endpoints", inds["endpoints"])
            if server:
                indicators["network"]["hosts"].add(server.rstrip(".").lower())
                indicators["network"]["emulated_servers"].add(server)
            if endpoint:
                indicators["network"]["emulated_endpoints"].add(endpoint)
                if endpoint.endswith(":53"):
                    indicators["network"]["dns_servers"].add(endpoint)
            if url:
                indicators["network"]["urls"].add(url)
            severity = "high" if endpoint and not endpoint.endswith(":53") else "medium"
            event = _side_event(
                "network",
                "network_events.traffic",
                ep_index,
                f"{proto or 'network'} {method} {endpoint or server or url}".strip(),
                severity,
                ["offline_emulation", "controlled_response"],
                sequence=sequence,
                server=server,
                host=server,
                port=port,
                proto=proto,
                method=method,
                path=path,
                url=url,
                endpoint=endpoint,
                headers=_shorten(headers, 260),
                data_preview=_shorten(data, 160),
            )
            all_events["network"].append(event)

        for call in ep.get("apis") or []:
            sequence += 1
            api_name = str(call.get("api_name") or "")
            if not api_name:
                continue
            api_counts[api_name] += 1
            module, func = _api_parts(api_name)
            api_module_counts[module or "other"] += 1
            args = call.get("args") or []
            lower_args = " ".join(str(a).lower() for a in args)

            if module in {"wininet", "winhttp", "ws2_32", "wsock32", "dnsapi", "urlmon"} or func in NETWORK_FUNCS:
                if func in {"htonl", "ntohl", "htons", "ntohs", "inet_ntoa"} and not _extract_indicators(args)["ips"]:
                    continue
                inds = _extract_indicators(args)
                _add_unique(indicators["network"], "ips", inds["ips"])
                _add_unique(indicators["network"], "domains", inds["domains"])
                _add_unique(indicators["network"], "urls", inds["urls"])
                _add_unique(indicators["network"], "endpoints", inds["endpoints"])
                severity = "medium"
                description = api_name
                extra: dict[str, Any] = {}
                if func.startswith("internetconnect") and len(args) >= 3:
                    host, port = str(args[1]), str(args[2])
                    handle = str(call.get("ret_val") or "")
                    if handle and handle != "0x0":
                        wininet_connect[handle] = {"host": host, "port": port}
                    description = f"InternetConnect host={host or '<empty>'} port={port}"
                    extra.update(host=host, port=port)
                    if host:
                        indicators["network"]["hosts"].add(host)
                elif func.startswith("httpopenrequest") and len(args) >= 3:
                    conn = wininet_connect.get(str(args[0])) or {}
                    method, path = str(args[1]), str(args[2])
                    host, port = str(conn.get("host") or ""), str(conn.get("port") or "")
                    url = ""
                    if host and path and not path.startswith("http"):
                        scheme = "https" if port.lower() in {"443", "0x1bb"} or "secure" in lower_args else "http"
                        url = f"{scheme}://{host}{path}"
                        indicators["network"]["urls"].add(url)
                    handle = str(call.get("ret_val") or "")
                    if handle and handle != "0x0":
                        wininet_request[handle] = {"method": method, "path": path, "host": host, "port": port, "url": url}
                    description = f"HTTP request open {method} {url or path}"
                    severity = "high"
                    extra.update(method=method, path=path, host=host, port=port, url=url)
                elif func.startswith("httpsendrequest"):
                    req = wininet_request.get(str(args[0])) or {}
                    headers = str(args[1]) if len(args) > 1 else ""
                    host_match = re.search(r"(?im)^host:\s*([^\\r\\n]+)", headers)
                    host = (host_match.group(1).strip() if host_match else str(req.get("host") or ""))
                    url = str(req.get("url") or "")
                    if host and not url and req.get("path"):
                        scheme = "https" if str(req.get("port")).lower() in {"443", "0x1bb"} else "http"
                        url = f"{scheme}://{host}{req.get('path')}"
                        indicators["network"]["urls"].add(url)
                    description = f"HTTP request send {req.get('method', '')} {url or req.get('path', '')}".strip()
                    severity = "high"
                    extra.update(method=req.get("method"), path=req.get("path"), host=host, url=url, headers=_shorten(headers, 260))
                elif func in {"connect", "sendto"}:
                    endpoint = inds["endpoints"][0] if inds["endpoints"] else ""
                    if endpoint:
                        indicators["network"]["endpoints"].add(endpoint)
                        if endpoint.endswith(":53"):
                            indicators["network"]["dns_servers"].add(endpoint)
                    description = f"{func} {endpoint}".strip()
                    severity = "high" if endpoint and not endpoint.endswith(":53") else "medium"
                    extra.update(endpoint=endpoint)
                elif "dnsquery" in func or func in {"gethostbyname", "getaddrinfo"}:
                    description = f"DNS/name lookup {args[0] if args else ''}".strip()
                    severity = "medium"
                event = _api_event("network", call, ep_index, sequence, description, severity, ["offline_emulation"], **extra)
                all_events["network"].append(event)
                continue

            if func in FILE_FUNCS:
                path = ""
                tags: list[str] = []
                severity = "low"
                description = api_name
                extra: dict[str, Any] = {}
                if func.startswith("createfile") and args:
                    path = str(args[0])
                    handle = str(call.get("ret_val") or "")
                    if handle and handle not in {"0x0", "0xffffffff", "-1"}:
                        handle_to_path[handle] = path
                    tags = _path_suspicious_tags(path)
                    write_intent = "generic_write" in lower_args or "create_" in lower_args
                    severity = _severity_for_file_event("create" if write_intent else "open", path)
                    description = f"CreateFile/Open {path}"
                    extra.update(path=path)
                elif func == "writefile":
                    handle = str(args[0]) if args else ""
                    path = handle_to_path.get(handle, "")
                    pe_like = any(_is_pe_like_value(a) for a in args)
                    severity = "high" if pe_like else ("medium" if path else "low")
                    description = f"WriteFile {path or handle}".strip()
                    extra.update(path=path, handle=handle, pe_like_data=pe_like)
                    if pe_like and path:
                        indicators["dropped_artifacts"]["pe_like_paths"].add(path)
                elif func == "readfile":
                    handle = str(args[0]) if args else ""
                    path = handle_to_path.get(handle, "")
                    description = f"ReadFile {path or handle}".strip()
                    extra.update(path=path, handle=handle)
                elif func.startswith("copyfile") and len(args) >= 2:
                    src, dst = str(args[0]), str(args[1])
                    tags = _path_suspicious_tags(dst)
                    severity = _severity_for_file_event("copy", dst)
                    description = f"CopyFile {src} -> {dst}"
                    extra.update(src=src, dst=dst, path=dst)
                    indicators["files"]["write_paths"].add(dst)
                elif func.startswith(("movefile", "deletefile", "createdirectory", "removedirectory", "setfileattributes", "findfirstfile", "findnextfile")) and args:
                    path = str(args[0])
                    tags = _path_suspicious_tags(path)
                    severity = _severity_for_file_event(func, path)
                    description = f"{func} {path}"
                    extra.update(path=path)
                if path:
                    indicators["files"]["paths"].add(path)
                    if severity in {"high", "medium"}:
                        indicators["files"]["write_paths"].add(path)
                all_events["files"].append(_api_event("files", call, ep_index, sequence, description, severity, tags, **extra))
                continue

            if module.startswith("advapi32") and func.startswith("reg"):
                key_path = _registry_key_from_args(args)
                if str(call.get("ret_val") or "") not in {"", "0x0"} and key_path.startswith("HKEY_"):
                    registry_handles[str(call.get("ret_val"))] = key_path
                if args and str(args[0]) in registry_handles:
                    key_path = registry_handles[str(args[0])]
                tags = _registry_tags(key_path)
                severity = "high" if "persistence_candidate" in tags or func.startswith(("regset", "regcreate")) else "medium"
                description = f"{func} {key_path}".strip()
                event = _api_event("registry", call, ep_index, sequence, description, severity, tags, key_path=key_path)
                all_events["registry"].append(event)
                if key_path:
                    indicators["registry"]["keys"].add(key_path)
                    if "persistence_candidate" in tags:
                        indicators["registry"]["persistence_candidates"].add(key_path)
                continue

            if module.startswith("advapi32") and func in SERVICE_FUNCS:
                name = _service_name(func, args)
                severity = "high" if func.startswith(("createservice", "startservice", "deleteservice", "changeserviceconfig")) else "medium"
                description = f"{func} {name}".strip()
                event = _api_event("services", call, ep_index, sequence, description, severity, service_name=name)
                all_events["services"].append(event)
                if name:
                    indicators["services"]["service_names"].add(name)
                continue

            if func in PROCESS_FUNCS:
                tags = []
                severity = "medium"
                description = api_name
                extra: dict[str, Any] = {}
                if func.startswith("createprocess") and args:
                    app = str(args[0])
                    cmdline = str(args[1]) if len(args) > 1 else ""
                    description = f"CreateProcess {app or cmdline}".strip()
                    extra.update(path=app, cmdline=cmdline)
                    if any(x in (app + " " + cmdline).lower() for x in LOLBIN_NAMES):
                        tags.append("lolbin_execution")
                        severity = "high"
                    indicators["process_injection"]["process_paths"].add(app)
                    if cmdline:
                        indicators["process_injection"]["cmdlines"].add(cmdline)
                elif "virtualalloc" in func or "virtualprotect" in func:
                    if "page_execute" in lower_args or "execute" in lower_args:
                        severity = "high"
                        tags.append("executable_memory")
                    description = f"{func} {' '.join(str(a) for a in args[-2:])}".strip()
                elif func in {"writeprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc", "ntqueueapcthread", "setwindowshookexa", "setwindowshookexw"}:
                    severity = "high"
                    tags.append("injection_api")
                    description = f"{func} called"
                elif func in {"winexec", "shellexecutea", "shellexecutew"}:
                    severity = "high"
                    description = f"{func} {' '.join(str(a) for a in args[:3])}".strip()
                event = _api_event("process_injection", call, ep_index, sequence, description, severity, tags, **extra)
                all_events["process_injection"].append(event)
                continue

            if module in {"bcrypt", "ncrypt", "crypt32"} or func in CRYPTO_FUNCS or func.startswith(("crypt", "bcrypt", "ncrypt")):
                algs = _crypto_algorithms(args)
                description = f"{api_name} {'/'.join(algs)}".strip()
                event = _api_event("crypto", call, ep_index, sequence, description, "medium" if algs else "low", algorithms=algs)
                all_events["crypto"].append(event)
                _add_unique(indicators["crypto"], "algorithms", algs)
                indicators["crypto"]["api_names"].add(api_name)
                continue

            if func in ANTI_ANALYSIS_FUNCS:
                tags = _anti_tags(func)
                severity = "medium" if "debugger_check" in tags else "low"
                description = f"{api_name} ({', '.join(tags)})"
                event = _api_event("anti_analysis", call, ep_index, sequence, description, severity, tags)
                all_events["anti_analysis"].append(event)
                indicators["anti_analysis"]["api_names"].add(api_name)
                _add_unique(indicators["anti_analysis"], "checks", tags)

    category_counts: dict[str, int] = {}
    for category in CATEGORY_ORDER:
        events, omitted = _dedupe_events(all_events[category], max_events_per_category)
        categories[category]["raw_event_count"] = len(all_events[category])
        categories[category]["count"] = len(events)
        categories[category]["events"] = events
        categories[category]["indicators"] = {
            key: sorted(values) for key, values in sorted(indicators[category].items())
        }
        if omitted:
            categories[category]["notes"].append(f"{omitted} duplicate/low-priority events omitted from JSON view")
        category_counts[category] = len(events)

    highlights = _build_highlights(categories)
    analysis = _build_analysis(categories)
    errors = [ep.get("error") for ep in entry_points if ep.get("error")]
    return {
        "schema": SCHEMA,
        "source_report": str(report_path),
        "sample": {
            "path": report.get("path") or report.get("binary") or "",
            "sha256": report.get("sha256") or "",
            "arch": report.get("arch") or "",
            "filetype": report.get("filetype") or "",
            "size": report.get("size"),
        },
        "emulation": {
            "speakeasy_version": report.get("emu_version"),
            "runtime_seconds": report.get("emulation_total_runtime"),
            "entry_points": len(entry_points),
            "api_calls_total": sum(api_counts.values()),
            "unique_apis": len(api_counts),
            "api_calls_by_module": dict(sorted(api_module_counts.items(), key=lambda item: (-item[1], item[0]))),
            "errors": errors[:5],
            "error_count": len(errors),
            "offline_note": (
                "Speakeasy was run as an emulator. In this project Docker networking defaults to none; "
                "network events show intent/API arguments, not confirmed external C2 contact."
            ),
        },
        "summary": {
            "category_counts": category_counts,
            "raw_category_counts": {name: len(all_events[name]) for name in CATEGORY_ORDER},
            "network_intent": category_counts.get("network", 0) > 0,
            "dropped_pe_like_artifacts": len(categories["dropped_artifacts"]["indicators"].get("pe_like_paths") or []),
            "possible_persistence": bool(categories["registry"]["indicators"].get("persistence_candidates")),
            "possible_injection_or_dynamic_code": category_counts.get("process_injection", 0) > 0,
            "crypto_observed": category_counts.get("crypto", 0) > 0,
            "anti_analysis_observed": category_counts.get("anti_analysis", 0) > 0,
            "c2_candidate_count": len(analysis.get("c2_candidates") or []),
            "behavior_chain_count": len(analysis.get("behavior_chains") or []),
            "highlights": highlights,
        },
        "analysis": analysis,
        "categories": categories,
    }


def _build_highlights(categories: dict[str, Any]) -> list[str]:
    highlights: list[str] = []
    net = categories["network"]["indicators"]
    if net.get("urls"):
        highlights.append("network URLs: " + ", ".join(net["urls"][:5]))
    elif net.get("endpoints"):
        highlights.append("network endpoints: " + ", ".join(net["endpoints"][:5]))
    elif net.get("hosts"):
        highlights.append("network hosts: " + ", ".join(net["hosts"][:5]))
    if net.get("dns_servers"):
        highlights.append("DNS traffic to: " + ", ".join(net["dns_servers"][:5]))
    drops = categories["dropped_artifacts"]["indicators"]
    if drops.get("pe_like_paths"):
        highlights.append("PE-like dropped artifacts: " + ", ".join(drops["pe_like_paths"][:5]))
    elif drops.get("paths"):
        highlights.append("dropped artifacts: " + ", ".join(drops["paths"][:5]))
    reg = categories["registry"]["indicators"]
    if reg.get("persistence_candidates"):
        highlights.append("registry persistence candidates: " + ", ".join(reg["persistence_candidates"][:5]))
    svc = categories["services"]["indicators"]
    if svc.get("service_names"):
        highlights.append("service activity: " + ", ".join(svc["service_names"][:5]))
    proc = categories["process_injection"]["indicators"]
    if proc.get("cmdlines"):
        highlights.append("process launches: " + ", ".join(proc["cmdlines"][:5]))
    crypto = categories["crypto"]["indicators"]
    if crypto.get("algorithms"):
        highlights.append("crypto algorithms: " + ", ".join(crypto["algorithms"][:8]))
    anti = categories["anti_analysis"]["indicators"]
    if anti.get("checks"):
        highlights.append("anti-analysis/environment checks: " + ", ".join(anti["checks"][:8]))
    return highlights[:12]


def _synthetic_or_local_endpoint(value: str) -> bool:
    low = (value or "").lower().strip()
    if not low:
        return True
    host = low
    if "://" in host:
        host = urlparse(host).hostname or host
    if ":" in host and host.count(":") == 1:
        host = host.rsplit(":", 1)[0]
    return host in {
        "default", "localhost", "0.0.0.0", "127.0.0.1", "198.51.100.10",
        "255.255.255.255",
    } or host.endswith(".local")


def _network_api_weight(events: list[dict[str, Any]]) -> tuple[str, list[str]]:
    apis = sorted({str(e.get("function") or e.get("api") or "") for e in events if e.get("source") == "api"})
    funcs = {a.lower().rsplit(".", 1)[-1] for a in apis}
    if funcs & {"httpsendrequesta", "httpsendrequestw", "winhttpsendrequest", "internetwritefile", "winhttpwritedata"}:
        return "high", apis[:12]
    if funcs & {"connect", "send", "sendto", "winhttpconnect", "internetconnecta", "internetconnectw"}:
        return "medium", apis[:12]
    return "low", apis[:12]


def _build_c2_candidates(categories: dict[str, Any]) -> list[dict[str, Any]]:
    net = categories.get("network") or {}
    indicators = net.get("indicators") or {}
    events = net.get("events") or []
    confidence, apis = _network_api_weight(events)
    candidates: dict[str, dict[str, Any]] = {}

    def add(kind: str, value: str, source: str, score: str | None = None) -> None:
        value = (value or "").strip()
        if not value or _synthetic_or_local_endpoint(value):
            return
        key = f"{kind}:{value.lower()}"
        item = candidates.setdefault(
            key,
            {
                "type": kind,
                "value": value,
                "confidence": score or confidence,
                "sources": [],
                "offline_emulated": True,
                "note": "Observed in Speakeasy API/network events; Docker network remains disabled.",
            },
        )
        if source not in item["sources"]:
            item["sources"].append(source)
        if score == "high" or item["confidence"] == "low":
            item["confidence"] = score or item["confidence"]

    for url in indicators.get("urls") or []:
        add("url", str(url), "network.urls", "high")
        host = urlparse(str(url)).hostname or ""
        add("host", host, "network.urls", "high")
    for host in (indicators.get("hosts") or []) + (indicators.get("domains") or []):
        add("host", str(host), "network.hosts")
    for endpoint in indicators.get("endpoints") or []:
        host = str(endpoint).rsplit(":", 1)[0]
        if _publicish_ip(host):
            add("endpoint", str(endpoint), "network.endpoints", "high")

    out = list(candidates.values())
    for item in out:
        if apis:
            item["supporting_apis"] = apis
    rank = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda x: (rank.get(str(x.get("confidence")), 3), str(x.get("value"))))
    return out[:50]


def _events_with(categories: dict[str, Any], category: str, *, tags: set[str] | None = None, funcs: set[str] | None = None) -> list[dict[str, Any]]:
    events = ((categories.get(category) or {}).get("events") or [])
    out = []
    for event in events:
        event_tags = set(event.get("tags") or [])
        func = str(event.get("function") or "").lower()
        if tags and event_tags & tags:
            out.append(event)
            continue
        if funcs and func in funcs:
            out.append(event)
    return out


def _seq(event: dict[str, Any]) -> int:
    try:
        return int(event.get("sequence") or 0)
    except (TypeError, ValueError):
        return 0


def _build_behavior_chains(categories: dict[str, Any]) -> list[dict[str, Any]]:
    chains: list[dict[str, Any]] = []
    net_events = (categories.get("network") or {}).get("events") or []
    file_writes = [
        e for e in (categories.get("files") or {}).get("events") or []
        if str(e.get("severity")) in {"medium", "high"} and (e.get("path") or e.get("dst"))
    ]
    drops = (categories.get("dropped_artifacts") or {}).get("events") or []
    proc_events = (categories.get("process_injection") or {}).get("events") or []
    persistence = _events_with(categories, "registry", tags={"persistence_candidate"})
    injection = _events_with(categories, "process_injection", tags={"injection_api", "executable_memory", "dynamic_code"})
    anti = (categories.get("anti_analysis") or {}).get("events") or []
    crypto = (categories.get("crypto") or {}).get("events") or []

    if file_writes and (drops or proc_events):
        chains.append({
            "name": "drop_or_stage_then_execute",
            "severity": "high",
            "evidence": [file_writes[0].get("description"), (drops or proc_events)[0].get("description")],
        })
    if persistence and (file_writes or drops):
        chains.append({
            "name": "persistence_after_file_activity",
            "severity": "high",
            "evidence": [persistence[0].get("description"), (file_writes or drops)[0].get("description")],
        })
    if injection:
        chains.append({
            "name": "process_injection_or_dynamic_code",
            "severity": "high",
            "evidence": [e.get("description") for e in injection[:3]],
        })
    if anti and net_events and min(_seq(e) for e in anti) <= max(_seq(e) for e in net_events):
        chains.append({
            "name": "environment_checks_before_or_during_network",
            "severity": "medium",
            "evidence": [anti[0].get("description"), net_events[0].get("description")],
        })
    if crypto and net_events:
        chains.append({
            "name": "crypto_and_network",
            "severity": "medium",
            "evidence": [crypto[0].get("description"), net_events[0].get("description")],
        })
    return chains[:20]


def _build_analysis(categories: dict[str, Any]) -> dict[str, Any]:
    c2 = _build_c2_candidates(categories)
    chains = _build_behavior_chains(categories)
    return {
        "c2_candidates": c2,
        "behavior_chains": chains,
        "confidence_notes": [
            "C2 candidates are network-intent leads from API arguments and emulated traffic, not proof of live C2.",
            "Synthetic lab IPs and localhost/default placeholders are filtered from candidates.",
        ],
    }


def behavior_to_text(behavior: dict[str, Any], max_events_per_category: int = 12) -> str:
    sample = behavior.get("sample") or {}
    emu = behavior.get("emulation") or {}
    summary = behavior.get("summary") or {}
    lines = [
        "Speakeasy behavior summary",
        f"Sample: {sample.get('path', '')}",
        f"SHA256: {sample.get('sha256', '')}",
        f"Arch/type: {sample.get('arch', '')} / {sample.get('filetype', '')}",
        f"Runtime: {emu.get('runtime_seconds')}s, API calls: {emu.get('api_calls_total', 0)}, errors: {emu.get('error_count', 0)}",
        "",
    ]
    highlights = summary.get("highlights") or []
    if highlights:
        lines.append("Highlights:")
        for item in highlights:
            lines.append(f"  - {item}")
        lines.append("")

    analysis = behavior.get("analysis") or {}
    c2_candidates = analysis.get("c2_candidates") or []
    if c2_candidates:
        lines.append("C2 candidates (offline intent, not live contact):")
        for item in c2_candidates[:8]:
            lines.append(f"  - {item.get('confidence', 'low')}: {item.get('type')} {item.get('value')}")
        lines.append("")
    chains = analysis.get("behavior_chains") or []
    if chains:
        lines.append("Behavior chains:")
        for item in chains[:8]:
            evidence = "; ".join(str(x) for x in (item.get("evidence") or []) if x)
            suffix = f" - {evidence}" if evidence else ""
            lines.append(f"  - {item.get('severity', 'medium')}: {item.get('name')}{suffix}")
        lines.append("")

    categories = behavior.get("categories") or {}
    for category in CATEGORY_ORDER:
        bucket = categories.get(category) or {}
        label = bucket.get("label") or CATEGORY_LABELS[category]
        count = int(bucket.get("count") or 0)
        raw_count = int(bucket.get("raw_event_count") or count)
        suffix = f", {raw_count} raw" if raw_count != count else ""
        lines.append(f"{label}: {count} event(s){suffix}")
        indicators = bucket.get("indicators") or {}
        for key, values in indicators.items():
            if values:
                joined = ", ".join(str(v) for v in values[:8])
                more = f" (+{len(values) - 8} more)" if len(values) > 8 else ""
                lines.append(f"  {key}: {joined}{more}")
        events = bucket.get("events") or []
        for event in events[:max_events_per_category]:
            sev = event.get("severity", "medium")
            desc = event.get("description", "")
            api = event.get("api", "")
            suffix = f" [{api}]" if api and api not in desc else ""
            lines.append(f"  - {sev}: {desc}{suffix}")
        if len(events) > max_events_per_category:
            lines.append(f"  ... {len(events) - max_events_per_category} more event(s)")
        lines.append("")
    lines.append(str(emu.get("offline_note") or "").strip())
    return "\n".join(lines).rstrip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract high-signal behavior from a Speakeasy JSON report")
    parser.add_argument("report", type=Path, help="Path to speakeasy_report_*.json")
    parser.add_argument("-o", "--output", type=Path, help="Write behavior JSON here")
    parser.add_argument("--summary", type=Path, help="Optional text summary output")
    parser.add_argument("--max-events-per-category", type=int, default=200)
    parser.add_argument("--text", action="store_true", help="Print text summary instead of JSON")
    args = parser.parse_args()

    if not args.report.is_file():
        print(f"[-] Not found: {args.report}", file=sys.stderr)
        return 1
    behavior = build_behavior(args.report, max_events_per_category=args.max_events_per_category)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(behavior, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(behavior_to_text(behavior) + "\n", encoding="utf-8")
    if not args.output:
        if args.text:
            print(behavior_to_text(behavior))
        else:
            print(json.dumps(behavior, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
