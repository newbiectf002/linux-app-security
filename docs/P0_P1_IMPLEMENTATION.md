# P0/P1 static scanner implementation

## Status

P0 and P1 are implemented as an offline-first static scan profile for ELF
executables and shared objects. The scanner does not execute target binaries and
does not call `ldd` on them. Every command keeps stdout, stderr, metadata, and
exit status under `raw/` before the result is normalized.

Tool output is never treated as a confirmed vulnerability by itself. Normalized
states remain separate:

- evidence-backed correlation: eligible for HTML and DefectDojo;
- review cue: visible only when an analyst needs to inspect a file;
- inventory/tool status: coverage information, not a finding;
- raw output: retained for traceability, excluded from compact reports.

## Coverage matrix

| Tier | Tool | Main checks | Normalized use |
|---|---|---|---|
| P0 | file, coreutils, binutils | CHK-01, CHK-03–06, CHK-12 | identity, hashes, ELF metadata, symbols, hardening |
| P0 | checksec 3.2.0 | CHK-05 | hardening cross-check |
| P0 | getcap/getfacl | CHK-03 | capabilities and ACL presence |
| P0 | lddtree | CHK-12 | static dependency-tree cross-check |
| P0 | strings | CHK-08/09/13/17 | capped high-signal URL/path/key-marker review cues |
| P1 | capa 9.4.0 | CHK-06/09/13/15/16/17 | compact capability-rule summary; selected high-signal matches enter review |
| P1 | cwe_checker | CHK-07 | candidate weaknesses; isolated Compose profile |
| P1 | YARA 4.5.0 | CHK-08/09/10/13/16/17/18 | conservative local-rule matches requiring manual validation |
| P1 | Syft 1.51.1 | CHK-12 | target-level SBOM/package count; full JSON retained only as raw evidence |
| P1 | Grype 0.118.0 | CHK-12 | candidate vulnerability count from the Syft SBOM |
| P1 | Trivy 0.73.0 secret scanner | CHK-08 | candidate secrets, mainly useful for extracted plaintext resources |
| P1 | ClamAV | CHK-17 | signature result requiring independent validation |

## Tool states

Optional collectors cannot abort a complete run. Their state is recorded as one
of `SUCCESS`, `TOOL_UNAVAILABLE`, `DATA_UNAVAILABLE`, `TIMEOUT`, `ERROR`, or
`SKIPPED_PREREQUISITE`. HTML aggregates these states so missing coverage is
visible without copying raw error logs into the report.

`cwe_checker` is the hardest P1 component to deploy because its analysis stack is
substantially larger than the other CLI binaries. It is therefore kept in the
`cwe-checker` Compose profile instead of inflating the main scanner image. The
main collector records `TOOL_UNAVAILABLE` unless a native `cwe_checker` command
is present.

## Network boundary

No scan command is required to access the Internet after data has been seeded.
Only these preparation operations need network access:

- build/pull pinned tool and container images;
- `scripts/update-offline-data.sh` for ClamAV signatures and the Grype database;
- optional future rule updates, performed as a separate reviewed operation;
- Codex authentication and model access when using the optional Codex profile.

Scans explicitly disable Grype automatic DB updates and Trivy DB updates. Syft,
capa, YARA, checksec, lddtree, getfacl, and strings work from local files.

## Compact outputs

Every successful CLI scan creates:

- `normalized/inventory.json`: full normalized inventory and compact tool summaries;
- `normalized/findings.json`: evidence-backed correlation findings only;
- `defectdojo-generic-findings.json`: automatically generated Generic Findings JSON;
- `report.html`: self-contained compact review report;
- `raw/`: complete evidence, excluded from HTML and DefectDojo payloads.

The HTML report contains summary metrics, executable/shared-object hardening
tables, compact actionable correlations with trace IDs, and tool coverage. It
does not embed SBOMs, full strings, symbol dumps, dependency dumps, raw logs, or
long remediation prose. Review strings are shown below a filename only when that
specific file has a review cue.

## Validation record

On 2026-09-16 the `research` image was built successfully and the pinned versions
were verified inside the container. A P1 static scan of the container's trusted
`/usr/bin/true` completed without executing the target and generated HTML plus a
valid DefectDojo JSON document. The experimental run is retained under
`output/experimental/runs/` as raw reproducibility evidence.

The optional Codex image was also built and `codex-cli 0.143.0` was verified.
The `cwe_checker:stable` image was pulled and its `cwe_checker 0.9.0` CLI was
verified. A full self-scan exceeded 90 seconds and was stopped, so a bounded
runtime experiment on a small fixture remains pending. Grype and ClamAV correctly returned
`DATA_UNAVAILABLE` before their databases were seeded; this is a coverage state,
not a clean security result.
