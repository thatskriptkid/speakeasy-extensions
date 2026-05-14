# Speakeasy Profiles

These are full JSON configuration files for `speakeasy-emulator==1.5.11`.
That version validates the whole config, so these files are intentionally not
small partial overlays. They are based on Mandiant's built-in `default.json`
with a Windows 11-like workstation identity and deterministic fake
filesystem/network responses.

Profiles are selected by `tools/run_speakeasy_docker.py` through
`SPEAKEASY_CONFIG_DIR` or, by default, this directory:

- `fast.json` - default pipeline profile, strings enabled, no memory tracing.
- `deep.json` - memory tracing plus retained freed memory.
- `children.json` - compatibility profile for child process emulation.

The runner always enables the dropped-file archive (`-z`). The default `fast`
profile avoids expensive tracing and child-process emulation. Memory tracing
(`-m`) and memory dumps (`-d`) are enabled by the `deep` profile, or memory dumps
can be forced with `--dump-dir`/`SPEAKEASY_MEMORY_DUMP=1`. Child-process
emulation (`-k`) is enabled only by the `children` profile or
`SPEAKEASY_EMULATE_CHILDREN=1`.

The profile identity intentionally avoids obvious sandbox strings: hostname
`WORKSTATION-01`, user `analyst`, ordinary Windows 11 registry keys, common
user directories, browser/tool paths and a non-VM-looking network adapter.
These values support anti-analysis checks without giving the sample real host
state.

The network section is an emulated Speakeasy model only. Docker still runs with
`--network none`; DNS/HTTP/winsock responses are controlled fake successes for
behavior discovery, not live C2 interaction.
