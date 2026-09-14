# Step 5 Batch 1 — Tool Research and Experimental Validation

## 1. Scope

This batch covers only CHK-01 through CHK-06. It does not perform code, secret,
network, certificate, SBOM/CVE, or malware scanning. A reported property or API
presence is raw evidence, not a confirmed vulnerability or severity assessment.

## 2. Environment

- Project image: `linux-app-security-research:latest`
- OS: Ubuntu 24.04.4 LTS
- Architecture: `x86_64`
- Runtime: Docker Engine 29.7.2 / Compose 5.4.0
- Main execution environment: disposable containers with the repository mounted
  at `/workspace`; no untrusted application was executed.
- Exact distro package versions are preserved in
  `raw/step5-batch1/environment/container.txt`.

The reproducible corpus includes three C/ELF hardening variants, a stripped copy,
DEB and RPM packages, a SquashFS Snap-like package, desktop entry, package.json,
JAR manifest, Flatpak metadata, systemd, Polkit, sudoers, and permission samples.
Generated binaries and packages remain ignored; sources and recipes are tracked.

## 3. Candidate tools evaluated

### file and GNU core/find utilities

- **Tool Name:** file; sha256sum/stat; find
- **Upstream Project:** https://github.com/file/file, GNU coreutils/findutils
- **License:** BSD-2-Clause for file; GPL-3.0-or-later for GNU utilities
- **Current Version Tested:** file 5.45; coreutils 9.4; findutils from Ubuntu 24.04
- **Install Method:** Ubuntu packages in the project image
- **Execution Environment:** Ubuntu container
- **Checks Covered:** CHK-01 and CHK-03
- **Checks Not Covered:** semantic package/framework/security conclusions
- **Input Types:** filesystem paths and arbitrary files
- **Machine-readable Output:** no native JSON; stable structured text is available
- **Offline Capability:** `OFFLINE_FULL`, tested with `--network none`
- **External/Rule Database Required:** no/no
- **Performance Notes:** fast, streaming, suitable for large trees
- **False-positive / Interpretation Risk:** file magic and modes need context
- **Maintenance Status:** maintained distro/upstream utilities
- **Advantages:** ubiquitous, deterministic, low dependency cost
- **Limitations:** aggregation and normalization require a future parser
- **Recommended Role:** `PRIMARY`

### GNU binutils

- **Tool Name:** readelf, objdump, nm, strings
- **Upstream Project:** https://sourceware.org/binutils/
- **License:** GPL-3.0-or-later
- **Current Version Tested:** 2.42
- **Install Method:** Ubuntu `binutils`
- **Execution Environment:** Ubuntu container
- **Checks Covered:** CHK-01, CHK-05, CHK-06
- **Checks Not Covered:** high-level framework inference and source-level behavior
- **Input Types:** ELF and object files
- **Machine-readable Output:** text only; `machine_readable: false`, `parser_required: true`
- **Offline Capability:** `OFFLINE_FULL`, tested with `--network none`; avoid
  optional debuginfod behavior when deterministic offline operation is required
- **External/Rule Database Required:** no/no for the commands tested
- **Performance Notes:** fast on the small corpus; no benchmark claim for large trees
- **False-positive / Interpretation Risk:** symbol/API presence is capability evidence only
- **Maintenance Status:** active upstream documentation and releases
- **Advantages:** authoritative low-level ELF evidence and broad architecture support
- **Limitations:** multiple commands and ELF knowledge are required
- **Recommended Role:** `PRIMARY`

### checksec

- **Tool Name:** checksec
- **Upstream Project:** https://github.com/slimm609/checksec
- **License:** BSD-3-Clause
- **Current Version Tested:** source tag 3.2.0, commit
  `c8afc72b017a693c94a64cde0955b143502c3f40`; locally built binary prints
  `dev` because upstream release ldflags were not applied
- **Install Method:** source tag built using Go 1.25 in an isolated container
- **Execution Environment:** Ubuntu container / static executable
- **Checks Covered:** CHK-05 aggregation: RELRO, canary, NX, PIE, RPATH,
  RUNPATH, FORTIFY and W^X-related indicators
- **Checks Not Covered:** complete debug-symbol, Build-ID, DT_NEEDED,
  interpreter, SONAME, and API inventory
- **Input Types:** ELF files
- **Machine-readable Output:** native JSON, YAML, XML and CSV
- **Offline Capability:** `OFFLINE_FULL` for file checks, experimentally tested
  in a container with `--network none`
- **External/Rule Database Required:** no/no for file checks
- **Performance Notes:** negligible on four small ELF files; not benchmarked at scale
- **False-positive / Interpretation Risk:** FORTIFY returned `Unknown/No` for a
  sample compiled with `_FORTIFY_SOURCE=2`; validate with symbols/compiler evidence
- **Maintenance Status:** active; 3.2.0 release/tag verified upstream
- **Advantages:** single static binary and useful structured aggregation
- **Limitations:** tag 3.2.0 lacks matching `v3.2.0` Go module tag, so documented
  `go install ...@v3.2.0` failed; source build requires Go >=1.25
- **Recommended Role:** `PRIMARY` aggregator with binutils as evidence authority

### dpkg-deb and rpm

- **Tool Name:** dpkg-deb; rpm/rpmbuild
- **Upstream Project:** https://www.debian.org/doc/debian-policy/ and https://rpm.org/docs/
- **License:** GPL-2.0-or-later
- **Current Version Tested:** dpkg 1.22.6ubuntu6.6; RPM 4.18.2
- **Install Method:** Ubuntu packages in the project image
- **Execution Environment:** Ubuntu container
- **Checks Covered:** CHK-01–CHK-03 package identity, dependencies, payload
  metadata, ownership/modes, and maintainer scripts
- **Checks Not Covered:** AppImage, Snap, Flatpak and semantic script safety
- **Input Types:** DEB and RPM
- **Machine-readable Output:** query-format/structured text; RPM supports custom
  query formats, but no native whole-result JSON was used in this test
- **Offline Capability:** `OFFLINE_FULL`, tested against local packages with no network
- **External/Rule Database Required:** no/no
- **Performance Notes:** fast on the synthetic packages
- **False-positive / Interpretation Risk:** declared metadata may differ from runtime state
- **Maintenance Status:** maintained native ecosystem tools
- **Advantages:** complete ecosystem-specific headers and hooks without installation
- **Limitations:** separate commands and normalization required
- **Recommended Role:** `PRIMARY`

### squashfs-tools / unsquashfs

- **Tool Name:** unsquashfs
- **Upstream Project:** https://github.com/plougher/squashfs-tools
- **License:** GPL-2.0-or-later
- **Current Version Tested:** 4.6.1
- **Install Method:** Ubuntu package in project image
- **Execution Environment:** Ubuntu container
- **Checks Covered:** CHK-01–CHK-03 filesystem and `meta/snap.yaml` materialization
- **Checks Not Covered:** Snap assertions/store metadata; authentic AppImage offset handling
- **Input Types:** SquashFS, including Snap payloads
- **Machine-readable Output:** text only; parser required
- **Offline Capability:** `OFFLINE_FULL`, local image tested
- **External/Rule Database Required:** no/no
- **Performance Notes:** fast on two-file corpus; no scale benchmark
- **False-positive / Interpretation Risk:** SquashFS alone does not prove package ecosystem
- **Maintenance Status:** maintained
- **Advantages:** extraction without executing package content
- **Limitations:** ecosystem semantics require manifest parsing
- **Recommended Role:** `PRIMARY` for Snap payload, `FALLBACK` for AppImage

### desktop-file-utils and structured manifest readers

- **Tool Name:** desktop-file-validate; jq; INI/XML/text readers
- **Upstream Project:** freedesktop.org desktop-file-utils; https://jqlang.org/
- **License:** GPL-2.0-or-later / MIT
- **Current Version Tested:** desktop-file-utils 0.27; jq 1.7.1
- **Install Method:** Ubuntu packages in isolated research container
- **Execution Environment:** Ubuntu container
- **Checks Covered:** CHK-01–CHK-04 manifest identity, entry commands, MIME/URI
  handlers, D-Bus flag, Snap confinement and Flatpak Context declarations
- **Checks Not Covered:** behavior behind an entry point and security conclusions
- **Input Types:** desktop, JSON, INI, XML and line-oriented manifests
- **Machine-readable Output:** JSON native for jq; others structured text/XML
- **Offline Capability:** jq/readers `OFFLINE_FULL`; desktop validator `NOT_TESTED`
  offline after installation
- **External/Rule Database Required:** no/no
- **Performance Notes:** negligible on the corpus
- **False-positive / Interpretation Risk:** declarations are not proof of runtime behavior
- **Maintenance Status:** distro-supported and standards-aligned
- **Advantages:** preserves context instead of searching isolated strings
- **Limitations:** several format-specific readers are needed
- **Recommended Role:** `PRIMARY` for declared entry metadata; `SUPPLEMENTARY`
  for security interpretation

No candidate was fully rejected. Generic `strings` is retained only as
`SUPPLEMENTARY`: it is noisy and loses semantic context, but it can expose API
references absent from dynamic symbols.

## 4. Experimental methodology

1. Verify official upstream, license and maintenance signals.
2. Pin and record tested package/source versions.
3. Build safe samples from tracked source/recipes.
4. Run tools read-only; never install or execute the sample applications.
5. Preserve raw stdout/stderr, install logs, commands and environment facts.
6. Compare checksec aggregation with readelf/nm/objdump evidence.
7. Re-run selected tools in a Docker container with `--network none`.
8. Record gaps as gaps rather than infer untested coverage.

## 5. Results per CHK

### CHK-01 — Application Information

`file`, SHA-256, ELF notes/headers and native package/manifests collectively
cover type, architecture, hash, Build ID, package identity and declared entry.
Runtime/framework and primary-executable selection remain evidence-based inference.

### CHK-02 — Package / Metadata / Manifest

DEB and RPM name/version/architecture/dependencies/file lists/hooks were read
without installing packages. Snap metadata was read from a generated SquashFS.
Desktop and JSON manifests were validated/parsed. Authentic AppImage and Flatpak
bundle workflows remain untested; raw Flatpak metadata was parsed only.

### CHK-03 — Permission / Privilege

`stat`, `find`, and `getcap` detected ownership, modes, a synthetic SetUID file,
world-writable file and file capability. systemd, sudoers, Polkit, Snap and
Flatpak declarations were collected as raw metadata. No privilege escalation
claim is made; cross-file correlation belongs to later evaluation/automation.

### CHK-04 — Entry Point / Handler

The INI-aware workflow retained Exec/TryExec/MimeType/action/D-Bus context.
`desktop-file-validate` caught the deliberately encountered filename contract
for D-Bus activation, after which the reverse-DNS filename validated. Package,
autostart and CLI entry-point discovery remains ecosystem/location-aware.

### CHK-05 — Native Binary Hardening

This was the deepest test. Variants covered Full/Partial/No RELRO, canary on/off,
PIE/non-PIE, NX/executable stack, RPATH, stripped/unstripped, Build ID on/off,
DT_NEEDED and interpreter. checksec gives machine-readable aggregation; binutils
provides the evidence needed for validation and the fields checksec omits.

### CHK-06 — OS/API Capability

`nm -D`, `readelf`, `objdump -T/-p`, and `strings` inventoried imports, exports,
DT_NEEDED and references for socket, dlopen, getenv, mmap/mprotect, EVP and SSL.
Dynamic resolution hides the eventual target of `dlsym`/`dlopen`. API presence
is capability evidence only, never proof of unsafe use.

## 6. Coverage gaps

- No authentic AppImage Type 1/2 sample: metadata/extraction coverage is unverified.
- No authentic Flatpak bundle/repository: only metadata format was exercised.
- No authentic signed Snap assertion: SquashFS payload and snap.yaml only.
- No static-linked or shared-object-with-SONAME positive ELF sample.
- No dedicated semantic validator for systemd, Polkit, sudoers, AppArmor or SELinux.
- Framework detection and privileged-helper correlation require explicit heuristics.
- checksec FORTIFY result needs independent validation.

### Potential Baseline Gap

None proven. Experimental gaps are tool/corpus gaps and do not justify editing
the approved Step 1–4 baseline.

## 7. Overlap

checksec overlaps readelf for common hardening flags but adds structured output.
readelf, objdump and nm overlap symbol/dynamic tables; retaining them is useful
for cross-checking and format-specific strengths. `file` overlaps ELF/package
identity but is a first-pass classifier, not the authoritative package parser.

## 8. Recommended toolset

- **Primary:** file, sha256sum/stat/find, GNU binutils, checksec, dpkg-deb,
  rpm, unsquashfs, desktop-file-validate plus format-aware readers.
- **Supplementary:** strings, getcap, manifest/location correlation.
- **Fallback:** raw INI/XML/text parsing for ecosystems without a tested native CLI.
- **Rejected:** none; no untested tool is selected.

## 9. Offline status

checksec file mode and the low-level/native package tools passed with Docker
`--network none`. Building/installing tools requires network during setup.
desktop-file-validate and getcap were functionally tested after isolated package
installation, but their explicit network-disabled rerun is `NOT_TESTED`.

## 10. Machine-readable output status

checksec JSON is native and validated. jq preserves native JSON. Most low-level
and package tools emit structured text; production parsers are deferred. RPM
queryformat can make deterministic records. No SARIF output was found/tested.

## 11. Risks / limitations

- Sample corpus is intentionally small and synthetic.
- Host filesystem mounts can affect ownership, modes and extended attributes.
- Aggregated labels must be traceable back to low-level evidence.
- Manifest declarations and imported symbols do not establish reachable behavior.
- Upstream version/tag/install inconsistencies must remain visible in bootstrap logs.

## 12. Recommendation for next batch

Human-review Batch 1 selections and gaps. Do not start Batch 2 until explicitly
authorized.
