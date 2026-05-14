# speakeasy-extensions

Additional API hooks, Docker packaging, behavior extraction, and corpus-hardening
tools for [Mandiant Speakeasy](https://github.com/mandiant/speakeasy).

This repo is designed to be applied on top of a normal Speakeasy install. It
does not contain malware samples, private corpus data, Windows DLLs, API keys,
or lab-specific configuration.

## What is included

- `patches/patch_speakeasy.py` - an idempotent patcher for
  `speakeasy-emulator==1.5.11`.
- `config/*.json` - three Windows-like profiles: `fast`, `deep`, and
  `children`.
- `tools/run_speakeasy_docker.py` - a Docker runner with offline networking,
  JSON reports, dropped-file archives, optional memory dumps, and module-dir
  support.
- `tools/speakeasy_behavior.py` - a normalized behavior extractor with
  categories for network, files, registry, services, process/injection, crypto,
  anti-analysis, and dropped artifacts.
- `tools/speakeasy_summary.py` and `tools/speakeasy_corpus_stats.py` - compact
  summaries and batch statistics for larger experiments.

## Quick start

Build a patched Speakeasy image:

```bash
docker build --platform linux/amd64 -t speakeasy-extensions:1.5.11 .
```

Run one sample without Internet access:

```bash
python3 tools/run_speakeasy_docker.py \
  --profile fast \
  --report-dir out/sample-001 \
  /path/to/sample.exe
```

The runner writes:

- `speakeasy_report_*.json` - Speakeasy JSON report.
- `speakeasy_report_*_summary.txt` - compact text summary.
- `speakeasy_behavior_*.json` - normalized behavior model.
- `speakeasy_network_*.json` - offline network-intent view.
- `speakeasy_dropped_*.zip` - dropped files archive, when present.
- `speakeasy_memory_*.zip` - memory dump archive for the `deep` profile or
  explicit memory-dump mode.

## Profiles

```bash
SPEAKEASY_PROFILE=fast      # default: fast enough for corpus triage
SPEAKEASY_PROFILE=deep      # adds memory tracing and memory dump
SPEAKEASY_PROFILE=children  # enables child process emulation
```

The default Docker network mode is `none`. Network API handlers return
controlled fake successes so you can observe intent without contacting live C2.

## Optional Windows module directories

Speakeasy can behave better when it sees real Windows PE modules. Do not commit
those DLLs to this repository. Mount your own module directories at runtime:

```bash
export SPEAKEASY_MODULE_DIR_X64=/path/to/windows/x64/modules
export SPEAKEASY_MODULE_DIR_X86=/path/to/windows/x86/modules
python3 tools/run_speakeasy_docker.py /path/to/sample.exe -o out/sample-001
```

The runner also accepts `--module-dir /path/to/modules` and passes it to
Speakeasy as `-l /modules`.

## Behavior extraction

You can run the behavior extractor on an existing report:

```bash
python3 tools/speakeasy_behavior.py out/report.json \
  -o out/behavior.json \
  --summary out/behavior.txt
```

The output is meant to be easier for humans and LLM pipelines to consume than a
raw Speakeasy trace. It keeps the original signal but groups it into malware
analysis categories.

## Apply without Docker

If you already have `speakeasy-emulator==1.5.11` installed in a virtualenv:

```bash
python -m pip install speakeasy-emulator==1.5.11
python patches/patch_speakeasy.py
speakeasy -t /path/to/sample.exe -o report.json -c config/fast.json
```

## License

This project is released under the MIT license. Speakeasy itself is maintained
by Mandiant/Google Cloud and is licensed separately in its upstream repository.
