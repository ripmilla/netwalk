# Changelog

Notable changes to netwalk, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The commit history is the detailed record — every commit message explains *why* a change
was made, not just what changed. `git log` and the **Blame** view on GitHub will always
tell you more than this file. What this file is for is answering "what is different since
I last upgraded" without reading thirty commits.

---

## [Unreleased]

### Added

- **Thai README** (`README.th.md`), linked from the top of the English one. A full translation
  rather than a summary — technical terms stay in English, which is how the people who will
  actually run this read and write about networks.

### Fixed

- **The audit read a MikroTik configuration dump as if it were command output.** Each check was
  given the slice of the file named after the command it runs — `/ip service print` — and a file
  holding the output of `/export` is not named that way: it is a dump of the whole configuration,
  organised by subsystem. No block matched, every MikroTik check came back as "not present", and
  a router with telnet enabled and SNMP v1/v2c open was reported clean. A check now finds the
  section of the dump its command prints, and carries a second pattern for the syntax a dump
  uses — `set telnet disabled=no`, not a `print` table.
  - **A dump is read by subsystem, not as one blob.** Scoping a check to the whole dump is worse
    than not reading it: `!remote-address` in a queue rule matches the logging check's pattern
    and turns "logs go nowhere" into a finding that is not true. A setting that belongs to
    another subsystem is not evidence about this one.
  - **A check the dump cannot decide is named, not passed.** RouterOS 7 does not export user
    accounts, so the default-admin check cannot be decided from a dump. It is reported as
    `NOT CHECKED`, with the reason, and produces no finding in either direction.
  - Command output still wins: a file carrying both the output of `/ip service print` and a
    dump is read as command output.
  - A dump copied into the directory by hand, with no `### /export` above it, is recognised by
    its shape and read the same way.
- **The audit counted an address once per sweep.** A host normally appears in two sweeps —
  the host sweep that decided it was alive, and the port scan that looked at it properly —
  so every unidentified address was counted twice. A real survey told the site owner that
  842 addresses could not be identified when there were 478. Addresses are counted once now,
  and a test says so.

### Tests

Audit 76, up from 57. The dump is tested in both directions: a vulnerable dump raises every
check it should, a hardened dump raises none, a check the dump cannot decide is named as
`NOT CHECKED` rather than passed, and command output still wins over a dump in the same file.
The dump's CRLF line endings and its wrapped settings are tested too.

---

## [0.2.0] — 2026-08-23

Surveys can now sweep an address range, check a configuration against vendor hardening
guidance, and be closed out properly. Both new capabilities are gated the same way the
read-only promise always was: in code, with tests, and with no override flag.

### Added

- **Authorised subnet sweep and well-known TCP port scan** (`netwalk_sweep.py`). The crawl
  finds what announces itself; the sweep finds the static-address server, the forgotten
  printer and the second firewall nobody remembers. A refused connection counts as a host
  found, so a box with every port closed still appears. Roughly 68 well-known ports by
  default, and the ones that are a finding on their own — telnet, SMB, RDP, VNC, Redis,
  Winbox, a database on a user VLAN — carry a stated reason.
  - **Third promise: it never sweeps a range nobody authorised.** A range must be written
    into the site's `scope.json` with the name of the person who authorised it, which then
    appears in the report. A range outside the scope is refused; so is a supernet of an
    authorised range; so is public address space without a second explicit flag; so is
    anything larger than a /16, and so is a projected probe count over the cap. There is
    no `--force`, and a test asserts there never will be.
  - `--via user@host` opens an `ssh -D` SOCKS tunnel for ranges only reachable from inside
    the site. RouterOS refuses dynamic forwarding, so for a MikroTik-only site the answer
    is the on-device `/tool ip-scan`, now on the read-only allowlist and required to carry
    `duration=`.
- **Hardening catalogue** (`netwalk_audit.py`) — 38 checks as data, so the same checks run
  on every site instead of depending on anyone remembering them. MikroTik, Cisco and Linux
  properly; Aruba, HP, Fortinet and Windows with a starter set the docs do not oversell.
  - Reads the configuration exports **off the disk**, so a config full of PSKs never passes
    through a model. Evidence excerpts are one line and go through the redactor.
  - `NOT CHECKED` is part of the output: a device with no export, a check whose command is
    missing, and every item needing a human are listed by name and written into
    `coverage.not_covered`.
  - `netwalk_audit.py guide` prints the checklist as a document, generated from the same
    data the checks run on, so the two cannot drift.
- **Seven `<vendor>.security.txt` command packs** feeding the catalogue. Every command in
  them is verified against the read-only gate by the policy suite.
- **`forget --with-configs`** shreds the site's configuration exports as well as the
  credential store. Without the flag, `forget` now reports how many exports are still on
  disk and how large — they hold PSKs and password hashes, and nothing else deleted them.
- **The full report names where the survey left its sensitive files** — credential store,
  configuration exports, and the fact that netwalk deletes neither by itself. Full copy
  only; the `--public` copy does not tell a customer where the engineer keeps passwords.
- **Address sweep section in the report**, with the authorisation, the blind spots and the
  addresses that are not in the inventory. Omitted from `--public`: a per-host list of open
  ports is a shopping list.
- **`tools/build_agents.py`** regenerates `AGENTS.md` from the skills. The file always
  claimed to be generated; now it is, and `--check` fails when it is stale.
- Record schema gained `sweeps[]` and `findings[].references[]`.

### Fixed

- **A community string reached a delivered report.** The renderer's sweep, which is
  supposed to refuse to build a report from a record holding credential material, anchored
  its pattern on the word `snmp` — so an evidence excerpt reading `trap-community: <value>`
  walked straight past it. The pattern now matches a community string under any prefix, and
  the same for secret/passphrase/psk/pre-shared-key. Already-redacted excerpts are exempt,
  because the first fix refused every report that had ever been cleaned. Both directions
  are tested, and the test was verified by reinstating the old pattern and watching it fail.
- **The audit reported one host twice and dropped findings silently.** A host is normally
  seen by two sweeps, and a finding was emitted per sweep rather than per host. Worse, every
  record-based finding carried a fixed id and the writer skips ids it already has, so three
  of four risky-port findings vanished with nothing said. Ports are merged per address, ids
  are qualified by their subject, and a test asserts every id in a run is unique.
- **A hardening check overruled a verified conclusion.** `mt-dns-remote` fires on
  `allow-remote-requests=yes`, which says the resolver will answer, not that anything can
  reach it. Checks gained an optional `confidence`; this one is `suspected` and its text
  says to read the raw firewall first.
- **MikroTik checks matched only one of two output shapes.** The patterns were written for
  `/ip service print` while the packs use `print detail`, so telnet, ftp, www, api and the
  default admin account silently passed on every real site. Both shapes are now covered and
  both are tested.
- `lastlog` was refused by the Linux allowlist (`last` with a word boundary does not match
  `lastlog`); it is plainly a read.
- `tests/test_audit.py` used `dict | None` in a signature without `from __future__ import
  annotations`, so it would not import on Python 3.9 — the version the README promises.

### Changed

- README documents the three promises, what the toolkit checks security-wise, and how to
  close a survey out. The credential form's loopback binding is shown with the socket line
  and a refused request from another host rather than asserted.
- `netwalk-scan` no longer says netwalk "is not a port scanner". It is one now, with a gate.

### Tests

651 cases, up from 341: policy 397 · sweep 81 (new) · audit 57 (new) · redaction 28 ·
credential receiver 25 · Omada 22 · map 16.

---

## [0.1.0] — 2026-08-22

First public release. A read-only network survey toolkit that ships as six Claude Code
skills and works from a plain terminal without an agent at all.

### Added

- **Two promises, enforced in code.** Every command is checked against a per-vendor
  read-only allowlist before it is sent (`netwalk_policy.py`); credentials are typed into a
  one-shot page served on the user's own `127.0.0.1` and never enter the conversation
  (`netwalk_cred.py`).
- Six skills: `netwalk` (the whole survey as one loop), `netwalk-login`, `netwalk-scan`,
  `netwalk-diag`, `netwalk-map`, `netwalk-fullreport`.
- Gated command runner with an evidence log (`netwalk_exec.py`), `--out` so a configuration
  export never passes through the conversation, and a secret redactor as a backstop.
- Read-only command packs for MikroTik RouterOS, Cisco IOS/IOS-XE/NX-OS, ArubaOS-CX,
  HP ProCurve & Comware, FortiOS, Junos, Linux and Windows; an unknown vendor falls back to
  a `show`/`display`/`get`/`print`-only profile rather than being unsupported.
- Controller adapters that read an adopted estate in one pass instead of device by device:
  **UniFi** (`netwalk_unifi.py`, Integration API and the legacy login) and **TP-Link Omada**
  (`netwalk_omada.py`, Open API and the older session API).
- Deterministic SVG topology renderer (`netwalk_map.py`) — vendor logo, hostname, management
  IP, model, OS version and live health per device, one box per internet uplink, port labels
  on every link, dashed for anything inferred.
- Self-contained HTML report (`netwalk_report.py`) with a `--public` mode, which refuses to
  render a record containing credential material.
- Scan record schema as the contract between collection and reporting.
- `install.py --agent` writes `AGENTS.md` and the equivalent instruction file for Cursor,
  Windsurf, Cline, Copilot, Gemini CLI, Continue, Aider and Codex.

### Notes

Tested end to end against a live customer site during development, which found eleven
defects the unit tests could not see — the diagram, the report and the credential form all
had faults that were only visible in the rendered artefact. Every one has a regression test.

[0.2.0]: https://github.com/ripmilla/netwalk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ripmilla/netwalk/releases/tag/v0.1.0
