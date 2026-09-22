import struct
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import analyze_sample  # noqa: E402
import pe_static  # noqa: E402
import run_speakeasy_docker as runner  # noqa: E402


def build_pe(
    *,
    kind: str = "exe",
    machine: int = 0x014C,
    dotnet: bool = False,
    with_api: bool = False,
) -> bytes:
    pe32plus = machine == 0x8664
    opt_size = 240 if pe32plus else 224
    characteristics = 0x22
    subsystem = 3
    if kind == "dll":
        characteristics |= 0x2000
        subsystem = 2
    elif kind == "sys":
        subsystem = 1
    payload = bytearray(0x400)
    if with_api:
        dll = b"KERNEL32.dll\x00"
        func = b"GetProcAddress\x00"
        payload[0x40 : 0x40 + len(dll)] = dll
        payload[0x82 : 0x82 + len(func)] = func
        struct.pack_into("<IIIII", payload, 0, 0x1060, 0, 0, 0x1040, 0x1060)
        if pe32plus:
            struct.pack_into("<Q", payload, 0x60, 0x1080)
        else:
            struct.pack_into("<I", payload, 0x60, 0x1080)
        struct.pack_into(
            "<IIHHIIIIIII",
            payload,
            0x100,
            0,
            0,
            0,
            0,
            0,
            1,
            1,
            1,
            0x1160,
            0x1140,
            0x1170,
        )
        struct.pack_into("<I", payload, 0x140, 0x1180)
        struct.pack_into("<I", payload, 0x160, 0x1000)
        struct.pack_into("<H", payload, 0x170, 0)
        export_name = b"DriverEntry\x00" if kind == "sys" else b"Start\x00"
        payload[0x180 : 0x180 + len(export_name)] = export_name

    header = bytearray(0x80 + 24 + opt_size + 40)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    header[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", header, 0x84, machine, 1, 0, 0, 0, opt_size, characteristics)
    optional = 0x98
    struct.pack_into("<H", header, optional, 0x20B if pe32plus else 0x10B)
    struct.pack_into("<I", header, optional + 16, 0x1000)
    if pe32plus:
        struct.pack_into("<Q", header, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", header, optional + 28, 0x400000)
    struct.pack_into("<H", header, optional + 68, subsystem)
    dir_count = optional + (108 if pe32plus else 92)
    dir_off = optional + (112 if pe32plus else 96)
    struct.pack_into("<I", header, dir_count, 16)
    if with_api:
        struct.pack_into("<II", header, dir_off, 0x1100, 40)
        struct.pack_into("<II", header, dir_off + 8, 0x1000, 40)
    if dotnet:
        struct.pack_into("<II", header, dir_off + 14 * 8, 0x2000, 8)
    section = optional + opt_size
    header[section : section + 6] = b".rdata"
    struct.pack_into("<IIII", header, section + 8, 0x400, 0x1000, 0x400, 0x400)
    header.extend(b"\x00" * (0x400 - len(header)))
    return bytes(header) + bytes(payload)


class PeStaticTests(unittest.TestCase):
    def test_classifies_exe_dll_sys(self):
        exe = pe_static.parse_pe(build_pe(kind="exe"), "a.exe")
        dll = pe_static.parse_pe(build_pe(kind="dll", machine=0x8664), "a.dll")
        sys = pe_static.parse_pe(build_pe(kind="sys"), "a.sys")
        self.assertEqual(exe["kind"], "exe")
        self.assertEqual(exe["arch"], "x86")
        self.assertEqual(exe["subsystem"], "windows_cui")
        self.assertEqual(dll["kind"], "dll")
        self.assertEqual(dll["arch"], "x64")
        self.assertEqual(dll["subsystem"], "windows_gui")
        self.assertEqual(sys["kind"], "sys")
        self.assertEqual(sys["subsystem"], "native")
        self.assertEqual(pe_static.entry_mode("dll"), "DllMain")
        self.assertEqual(pe_static.entry_mode("dll", all_exports=True), "all_exports")
        self.assertEqual(pe_static.entry_mode("sys"), "DriverEntry")

    def test_reads_import_and_export(self):
        parsed = pe_static.parse_pe(build_pe(kind="dll", with_api=True), "hook.dll")
        self.assertEqual(parsed["imports"][0]["dll"], "KERNEL32.dll")
        self.assertEqual(parsed["imports"][0]["imports"], ["GetProcAddress"])
        self.assertEqual(parsed["exports"], ["Start"])

    def test_marks_dotnet_without_emulation(self):
        parsed = pe_static.parse_pe(build_pe(kind="exe", dotnet=True), "app.exe")
        self.assertTrue(parsed["dotnet"])

    def test_rejects_shellcode_bytes(self):
        self.assertIsNone(pe_static.parse_pe(b"\x90\x90\xc3", "blob.bin"))


class ReportTests(unittest.TestCase):
    def test_fast_dll_report_mentions_dllmain_only(self):
        sample = Path("hook.dll")
        plan = analyze_sample.emulation_plan("dll", raw=False, all_exports=False)
        report = analyze_sample.build_report(
            sample_path=sample,
            sha256="ab" * 32,
            size=128,
            static=pe_static.parse_pe(build_pe(kind="dll", with_api=True), "hook.dll"),
            plan=plan,
            profile="fast",
            timeout=60,
            exit_code=0,
            behavior={
                "emulation": {"api_calls_total": 4, "runtime_seconds": 1.2, "error_count": 0},
                "summary": {"highlights": ["loaded kernel32"]},
                "categories": {"network": {"count": 0}},
                "analysis": {},
            },
        )
        text = analyze_sample.report_to_markdown(report)
        self.assertEqual(report["schema"], analyze_sample.SCHEMA)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["emulation"]["entry_mode"], "DllMain")
        self.assertIn("DllMain", text)
        self.assertIn("--all-exports", text)
        self.assertIn("GetProcAddress", text)
        self.assertFalse(plan["all_entrypoints"])

    def test_sys_plan_is_driver_entry(self):
        plan = analyze_sample.emulation_plan("sys", raw=False, all_exports=False)
        self.assertEqual(plan["entry_mode"], "DriverEntry")
        self.assertFalse(plan["all_entrypoints"])
        self.assertEqual(runner.entrypoint_docker_args(False), ["-e", "SPEAKEASY_ALL_ENTRYPOINTS=0"])
        self.assertEqual(runner.entrypoint_docker_args(None), [])

    def test_non_pe_does_not_call_docker(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary) / "blob.bin"
            sample.write_bytes(b"\x90\x90\xc3")
            code = analyze_sample.main([str(sample), "-o", str(Path(temporary) / "out")])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
