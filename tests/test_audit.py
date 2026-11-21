#!/usr/bin/env python3
"""Regression suite for the netwalk hardening catalogue.

A hardening check has two ways to be wrong and only one of them is loud:

  * a **false positive** makes the engineer argue with a customer about a finding
    that is not real, and it gets noticed the same day
  * a **false negative** reads exactly like a clean result, and nobody ever finds out

So every check here is tested twice: against a device that has the problem, and
against the same device configured properly. A pattern that fires on the vulnerable
fixture but also fires on the hardened one has not been shown to work.

The MikroTik cases run against BOTH RouterOS output shapes - `print` and
`print detail` - because the first version of this catalogue matched only the terse
one and silently passed every real site, where the packs use `print detail`.

Run after ANY edit to netwalk_audit.py:  python3 tests/test_audit.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

_TMP = tempfile.mkdtemp(prefix="netwalk-audit-test-")
os.environ["NETWALK_HOME"] = _TMP

import netwalk_audit as A  # noqa: E402

FAILED: list[str] = []
PASSED = 0


def ok(label):
    global PASSED
    PASSED += 1
    print(f"  ok     {label}")


def bad(label, detail=""):
    FAILED.append(f"{label}{(' - ' + detail) if detail else ''}")
    print(f"  FAILED {label}{(' - ' + detail) if detail else ''}")


def check(cond, label, detail=""):
    ok(label) if cond else bad(label, detail)


# --------------------------------------------------------------------- fixtures

MT_VULNERABLE_DETAIL = '''### /ip service print detail
Flags: X - disabled, I - invalid
 0   name="telnet" port=23
 1   name="ftp" port=21
 2   name="www" port=80
 3   name="ssh" port=22
 4   name="api" port=8728
### /ip firewall filter print detail
 0    chain=input action=accept connection-state=established,related
### /snmp community print detail
 0   name="public" addresses=0.0.0.0/0
### /tool romon print
                      enabled: yes
### /ip neighbor discovery-settings print
  discover-interface-list: all
### /tool mac-server print
  allowed-interface-list: all
### /tool bandwidth-server print
  enabled: yes
### /ip socks print
  enabled: yes
### /ip dns print
  allow-remote-requests: yes
### /system ntp client print
  enabled: no
### /system logging action print
 0   name="memory" target=memory
### /user print detail
 0   name="admin" group=full
'''

MT_VULNERABLE_TERSE = '''### /ip service print
Flags: X - disabled, I - invalid
 #   NAME   PORT
 0   telnet   23
 1   ftp      21
 2   www      80
 3   ssh      22
 4   api    8728
### /ip firewall filter print
 0    chain=input action=accept connection-state=established,related
### /snmp community print
 0   public  0.0.0.0/0
### /tool romon print
                      enabled: yes
### /ip neighbor discovery-settings print
  discover-interface-list: all
### /tool mac-server print
  allowed-interface-list: all
### /tool bandwidth-server print
  enabled: yes
### /ip socks print
  enabled: yes
### /ip dns print
  allow-remote-requests: yes
### /system ntp client print
  enabled: no
### /system logging action print
 0   memory  memory
### /user print
 0   admin  full
'''

MT_HARDENED = '''### /ip service print detail
Flags: X - disabled, I - invalid
 0 X name="telnet" port=23
 1 X name="ftp" port=21
 2 X name="www" port=80
 3   name="ssh" port=22 address=10.0.0.0/24
 4 X name="api" port=8728
 5   name="api-ssl" port=8729 address=10.0.0.0/24
 6   name="www-ssl" port=443 address=10.0.0.0/24
### /ip firewall filter print detail
 0    chain=input action=accept connection-state=established,related
 1    chain=input action=accept src-address=10.0.0.0/24
 2    chain=input action=drop
### /snmp community print detail
 0   name="mon-v3-only" authentication-protocol=SHA1 encryption-protocol=AES
### /tool romon print
                      enabled: no
### /ip neighbor discovery-settings print
  discover-interface-list: LAN
### /tool mac-server print
  allowed-interface-list: MGMT
### /tool bandwidth-server print
  enabled: no
### /ip socks print
  enabled: no
### /ip dns print
  allow-remote-requests: no
### /system ntp client print
  enabled: yes
### /system logging action print
 0   name="remote" target=remote remote=10.0.0.9
### /user print detail
 0   name="noc-somchai" group=full
'''

# A RouterOS configuration dump, the way `netwalk_exec.py run --out` saves the
# output of `/export verbose`. The settings are the same ones the command
# fixtures above carry, in the shape a dump writes them: `set <name> key=value`.
# The `### /export verbose` line is netwalk_exec's own marker, naming the
# command whose output follows - the dump itself does not contain a `###` line.
MT_DUMP_VULNERABLE = '''### /export verbose
# 2026-01-14 09:05:00 by RouterOS 7.15.3
# model = RB5009UG+S
/ip service
set ftp address="" disabled=no max-sessions=20 port=21 vrf=main
set ssh address=10.0.0.0/8 disabled=no max-sessions=20 port=22 vrf=main
set telnet address=10.0.0.0/8 disabled=no max-sessions=20 port=23 vrf=main
set www address="" disabled=no max-sessions=20 port=88 vrf=main
set api address="" disabled=no max-sessions=20 port=8728 vrf=main
/ip firewall filter
add action=accept chain=input connection-state=established,related
/snmp community
set [ find default=yes ] addresses=0.0.0.0/0 authentication-protocol=MD5 \\
    disabled=no encryption-protocol=DES name=public read-access=yes security=none
/tool romon
set enabled=yes id=00:00:00:00:00:00
/tool mac-server
set allowed-interface-list=all
/ip neighbor discovery-settings
set discover-interface-list=all discover-interval=30s
/tool bandwidth-server
set allocate-udp-ports-from=2000 authenticate=yes enabled=yes max-sessions=100
/ip socks
set auth-method=none enabled=yes port=1080 version=4 vrf=main
/ip dns
set allow-remote-requests=yes cache-size=2048KiB servers=1.1.1.1
/system ntp client
set enabled=no mode=unicast servers=pool.ntp.org
/system logging action
set 0 memory-lines=1000 name=memory target=memory
/queue simple
set name=voip !parent-queue !queue-type !rate-limit !remote-address target=ether8
'''

MT_DUMP_HARDENED = '''### /export verbose
# 2026-01-14 09:05:00 by RouterOS 7.15.3
/ip service
set ftp address="" disabled=yes max-sessions=20 port=21 vrf=main
set telnet address=10.0.0.0/8 disabled=yes max-sessions=20 port=23 vrf=main
set www address="" disabled=yes max-sessions=20 port=88 vrf=main
set www-ssl address="" certificate=none disabled=no max-sessions=20 port=443 \\
    tls-version=any vrf=main
set api address="" disabled=yes max-sessions=20 port=8728 vrf=main
set api-ssl address="" certificate=cert01 disabled=no max-sessions=20 port=8729 \\
    tls-version=any vrf=main
set ssh address=10.0.0.0/8 disabled=no max-sessions=20 port=22 vrf=main
/ip firewall filter
add action=accept chain=input connection-state=established,related
add action=drop chain=input
/snmp community
set [ find default=yes ] addresses=10.0.0.9/32 authentication-protocol=SHA1 \\
    encryption-protocol=AES name=mon-v3-only read-access=yes security=private
/tool romon
set enabled=no id=00:00:00:00:00:00
/tool mac-server
set allowed-interface-list=MGMT
/ip neighbor discovery-settings
set discover-interface-list=LAN discover-interval=30s
/tool bandwidth-server
set allocate-udp-ports-from=2000 authenticate=yes enabled=no max-sessions=100
/ip socks
set auth-method=none enabled=no port=1080 version=4 vrf=main
/ip dns
set allow-remote-requests=no cache-size=2048KiB servers=1.1.1.1
/system ntp client
set enabled=yes mode=unicast servers=pool.ntp.org
/system logging action
set 0 name=remote remote=10.0.0.9 remote-port=514 target=remote
'''

IOS_VULNERABLE = '''### show running-config
version 15.2
enable password cisco123
ip http server
snmp-server community public RO
line vty 0 15
 transport input telnet
 exec-timeout 0 0
'''

IOS_HARDENED = '''### show running-config
version 15.2
service password-encryption
aaa new-model
enable secret 5 $1$abcd$xxxxxxxxxxxxxxxxxxxxx0
no ip http server
snmp-server community m0nit0r-str1ng RO 20
logging host 10.0.0.9
spanning-tree portfast bpduguard default
ip dhcp snooping
line vty 0 15
 transport input ssh
 exec-timeout 10 0
'''

LNX_VULNERABLE = '''### cat /etc/ssh/sshd_config
PermitRootLogin yes
PasswordAuthentication yes
### iptables -S
-P INPUT ACCEPT
### ss -tulpn
tcp   LISTEN 0  128  0.0.0.0:23   0.0.0.0:*
### cat /etc/sudoers
%wheel ALL=(ALL) NOPASSWD: ALL
'''

LNX_HARDENED = '''### cat /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
### iptables -S
-P INPUT DROP
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp --dport 22 -j ACCEPT
### ss -tulpn
tcp   LISTEN 0  128  0.0.0.0:22   0.0.0.0:*
### cat /etc/sudoers
%wheel ALL=(ALL) ALL
'''


def audit(site: str, host: str, vendor: str, config: str, extra_record: dict | None = None):
    """Write a fixture to disk exactly as netwalk_exec --out would, then audit it."""
    d = A.C.site_dir(site)
    (d / "configs").mkdir(parents=True, exist_ok=True)
    (d / "configs" / f"{host}.security.txt").write_text(config, encoding="utf-8")
    rec = {"site": {"id": site}, "scanned_at": "t",
           "devices": [{"host_id": host, "vendor": vendor, "reachable": True}]}
    if extra_record:
        rec.update(extra_record)
    findings, not_checked = A.run_checks(site, rec)
    return {f["id"].split("@")[0] for f in findings}, findings, not_checked


# ------------------------------------------------------------------ the tests

def test_mikrotik_both_formats():
    print("\nMikroTik - the vulnerable box, in both RouterOS output shapes")
    want = {"mt-telnet-enabled", "mt-ftp-enabled", "mt-www-plain", "mt-api-plain",
            "mt-input-no-drop", "mt-snmp-v1v2", "mt-romon-enabled", "mt-mac-server-all",
            "mt-discovery-all", "mt-bandwidth-server", "mt-socks-upnp", "mt-dns-remote",
            "mt-no-ntp", "mt-no-remote-logging", "mt-default-admin"}
    for label, fixture in (("print detail", MT_VULNERABLE_DETAIL), ("print", MT_VULNERABLE_TERSE)):
        got, _, _ = audit(f"mt-{label.replace(' ', '-')}", "gw", "mikrotik", fixture)
        missing = want - got
        check(not missing, f"every MikroTik check fires on the {label} format",
              f"missed: {sorted(missing)}")

    print("\nMikroTik - the hardened box must be silent")
    got, _, _ = audit("mt-hardened", "gw", "mikrotik", MT_HARDENED)
    check(not got, "a properly configured RouterOS produces no findings", f"got: {sorted(got)}")


def test_disabled_is_not_enabled():
    print("\nthe X flag - a disabled service is not a finding")
    fixture = ('### /ip service print detail\n'
               'Flags: X - disabled\n'
               ' 0 X name="telnet" port=23\n'
               ' 1 X name="ftp" port=21\n'
               ' 2   name="ssh" port=22\n')
    got, _, _ = audit("mt-x", "gw", "mikrotik", fixture)
    check("mt-telnet-enabled" not in got, "telnet marked X does not raise a finding")
    check("mt-ftp-enabled" not in got, "ftp marked X does not raise a finding")

    ssl = ('### /ip service print detail\n'
           ' 0   name="www-ssl" port=443\n'
           ' 1   name="api-ssl" port=8729\n')
    got, _, _ = audit("mt-ssl", "gw", "mikrotik", ssl)
    check("mt-www-plain" not in got, "www-ssl is not mistaken for plain www")
    check("mt-api-plain" not in got, "api-ssl is not mistaken for the clear-text api")


def test_mikrotik_dump():
    print("\nMikroTik - the same box, as a configuration dump instead of command output")
    want = {"mt-telnet-enabled", "mt-ftp-enabled", "mt-www-plain", "mt-api-plain",
            "mt-input-no-drop", "mt-snmp-v1v2", "mt-romon-enabled", "mt-mac-server-all",
            "mt-discovery-all", "mt-bandwidth-server", "mt-socks-upnp", "mt-dns-remote",
            "mt-no-ntp", "mt-no-remote-logging"}
    got, findings, nc = audit("mt-dump", "gw", "mikrotik", MT_DUMP_VULNERABLE)
    missing = want - got
    check(not missing, "every MikroTik check fires on a configuration dump",
          f"missed: {sorted(missing)}")
    check("mt-default-admin" not in got,
          "a check the dump cannot decide is not silently reported as clean")

    print("\nMikroTik - a dump is read by subsystem, not as one blob")
    check("mt-no-remote-logging" in got,
          "a `!remote-address` in a queue rule does not decide the logging check",
          f"got: {sorted(got)}")
    check(any("mt-default-admin" in n for n in nc),
          "a check whose section the dump does not carry is named as NOT CHECKED")
    check(not any("mt-default-admin" in f["id"] for f in findings),
          "and it produces no finding either way")

    print("\nMikroTik - the hardened dump must be silent")
    got, _, _ = audit("mt-dump-hardened", "gw", "mikrotik", MT_DUMP_HARDENED)
    check(not got, "a properly configured RouterOS dump produces no findings",
          f"got: {sorted(got)}")


def test_dump_cannot_decide_is_not_clean():
    print("\nhonesty - a check the dump cannot decide says so")
    dump = ('### /export verbose\n'
            '/user\n'
            'add group=full name=admin password=whatever\n')
    got, _, nc = audit("mt-dump-user", "gw", "mikrotik", dump)
    check("mt-default-admin" not in got,
          "a check with no dump-side pattern does not produce a finding")
    check(any("mt-default-admin" in n for n in nc),
          "and it is reported as NOT CHECKED rather than passed")
    check(any("cannot be decided" in n for n in nc),
          "and the reason says the dump is not the shape the check reads",
          f"got: {nc}")


def test_command_output_wins_over_a_dump():
    print("\nprecedence - command output is used when the file carries both")
    both = ('### /ip service print detail\n'
            ' 0   name="telnet" port=23\n'
            '### /export verbose\n'
            '/ip service\n'
            'set telnet address="" disabled=yes max-sessions=20 port=23 vrf=main\n')
    got, _, _ = audit("mt-both", "gw", "mikrotik", both)
    check("mt-telnet-enabled" in got,
          "the command output decides the check when the file has one",
          f"got: {sorted(got)}")


def test_unmarked_dump_is_still_a_dump():
    print("\nMikroTik - a dump copied in by hand, with nothing above it")
    bare = MT_DUMP_VULNERABLE.split("\n", 1)[1]      # drop the `### /export verbose` marker
    got, _, _ = audit("mt-dump-bare", "gw", "mikrotik", bare)
    check("mt-telnet-enabled" in got,
          "a dump with no marker is still read, not silently reported as clean",
          f"got: {sorted(got)}")
    check("mt-no-remote-logging" in got,
          "and it is read by subsystem, not as one blob",
          f"got: {sorted(got)}")

    print("\nMikroTik - and a hardened dump is still silent")
    bare_ok = MT_DUMP_HARDENED.split("\n", 1)[1]
    got, _, _ = audit("mt-dump-bare-hardened", "gw", "mikrotik", bare_ok)
    check(not got, "a hardened dump with no marker produces no findings",
          f"got: {sorted(got)}")

    print("\nCisco - a config that is not a dump is not read as one")
    got, _, _ = audit("cisco-bare", "gw", "cisco", IOS_VULNERABLE.split("\n", 1)[1])
    check("cis-enable-password" in got,
          "an unmarked Cisco config still produces its findings",
          f"got: {sorted(got)}")


def test_dump_line_endings():
    print("\nMikroTik - RouterOS ends its lines with CRLF")
    crlf = MT_DUMP_VULNERABLE.replace("\n", "\r\n")
    sections = A.export_sections(crlf)
    check("/ip service" in sections, "a CRLF dump is split into its sections",
          f"got: {sorted(sections)}")
    service = sections.get("/ip service", "")
    check("disabled=no" in service,
          "a setting is read out of a CRLF section",
          f"got: {service[:160]}")
    snmp = sections.get("/snmp community", "")
    check("name=public" in snmp and "\\" not in snmp,
          "a setting wrapped over two lines is folded back into one",
          f"got: {snmp[:200]}")


def test_cisco():
    print("\nCisco")
    want = {"cis-no-password-encryption", "cis-enable-password", "cis-vty-telnet",
            "cis-http-server", "cis-snmp-default-community", "cis-no-aaa",
            "cis-no-logging-host", "cis-no-bpduguard", "cis-no-dhcp-snooping",
            "cis-vty-no-timeout"}
    got, _, _ = audit("ios-bad", "sw", "cisco", IOS_VULNERABLE)
    missing = want - got
    check(not missing, "every Cisco check fires on the vulnerable config",
          f"missed: {sorted(missing)}")
    got, _, _ = audit("ios-good", "sw", "cisco", IOS_HARDENED)
    check(not got, "a hardened IOS config produces no findings", f"got: {sorted(got)}")


def test_linux():
    print("\nLinux")
    want = {"lnx-ssh-root-login", "lnx-ssh-password-auth", "lnx-empty-firewall",
            "lnx-clear-text-services", "lnx-nopasswd-sudo"}
    got, _, _ = audit("lnx-bad", "srv", "linux", LNX_VULNERABLE)
    missing = want - got
    check(not missing, "every Linux check fires on the vulnerable host",
          f"missed: {sorted(missing)}")
    got, _, _ = audit("lnx-good", "srv", "linux", LNX_HARDENED)
    check(not got, "a hardened Linux host produces no findings", f"got: {sorted(got)}")


def test_vendor_isolation():
    print("\nvendor scoping - a check only runs against the gear it was written for")
    got, _, _ = audit("wrong-vendor", "gw", "cisco", MT_VULNERABLE_DETAIL)
    check(not any(g.startswith("mt-") for g in got),
          "MikroTik checks do not run against a device recorded as Cisco", f"got: {sorted(got)}")
    for vendor in ("mikrotik", "cisco", "linux", "aruba", "hp", "fortinet", "windows", ""):
        sel = A.checks_for(vendor)
        check(all("*" in c["vendors"] or vendor in c["vendors"] for c in sel),
              f"checks_for({vendor or 'unknown'!r}) returns only applicable checks")


def test_record_checks():
    print("\nrecord checks - decided from structured fields, not from text")
    rec = {
        "site": {"id": "rc"}, "scanned_at": "t",
        "devices": [{"host_id": "gw", "vendor": "mikrotik", "reachable": True,
                     "mgmt_exposure": {"reachable_from_wan": ["winbox/8291"]},
                     "wireless_networks": [
                         {"ssid": "Open", "security": "open"},
                         {"ssid": "Old", "security": "wep"},
                         {"ssid": "Fine", "security": "wpa2-enterprise"},
                         {"ssid": "Guest", "security": "wpa2-personal",
                          "guest": True, "client_isolation": False}]}],
        "sweeps": [{"range": "10.0.0.0/24", "method": "tcp-connect", "authorized_by": "owner",
                    "hosts": [{"ip": "10.0.0.9", "open_ports": [23, 3389],
                               "services": ["telnet", "rdp"], "in_record": False},
                              {"ip": "10.0.0.1", "open_ports": [22], "services": ["ssh"],
                               "in_record": True}]}],
    }
    findings, _ = A.run_checks("rc", rec)
    ids = [f["id"].split("@")[0] for f in findings]
    check(len(set(f["id"] for f in findings)) == len(findings),
          "every finding id is unique - a shared id is silently dropped when the record "
          "is written, which loses findings without saying so")
    titles = " | ".join(f["title"] for f in findings)

    check("rec-mgmt-on-wan" in ids, "management on a WAN address is critical",
          str(sorted(set(ids))))
    check(next(f["severity"] for f in findings
                    if f["id"].startswith("rec-mgmt-on-wan")) == "critical",
          "and it is rated critical")
    check("'Open' uses open security" in titles, "an open SSID is caught")
    check("'Old' uses wep security" in titles, "a WEP SSID is caught")
    check("'Fine'" not in titles.split("Guest")[0] or "wpa2-enterprise" not in titles,
          "a WPA2-Enterprise SSID is not flagged as weak")
    check("client isolation" in titles, "a guest SSID without isolation is caught")
    check("rec-risky-open-port" in ids, "telnet/RDP from the sweep becomes a finding")
    check("rec-unidentified-host" in ids, "an unidentified swept address becomes a finding")
    check(all(f.get("public_safe") is False for f in findings),
          "every hardening finding defaults to public_safe=false - none of this belongs "
          "in a copy handed to a third party")
    check(all(f.get("evidence") for f in findings), "every finding carries evidence")
    check(all(f.get("recommendation") for f in findings), "every finding carries a fix")


def test_one_finding_per_host_across_sweeps():
    print("\nsweeps - a host in two sweeps is one finding, not two")
    rec = {"site": {"id": "ms"}, "scanned_at": "t", "devices": [],
           "sweeps": [
               {"range": "10.0.0.0/24", "method": "tcp-connect", "authorized_by": "o",
                "hosts": [{"ip": "10.0.0.7", "open_ports": [23, 445],
                           "services": ["telnet", "smb"], "in_record": False}]},
               {"range": "10.0.0.7", "method": "tcp-connect", "authorized_by": "o",
                "hosts": [{"ip": "10.0.0.7", "open_ports": [23, 445, 5900, 111],
                           "services": ["telnet", "smb", "vnc", "rpcbind"],
                           "in_record": False}]}]}
    findings, _ = A.run_checks("ms", rec)
    risky = [f for f in findings if f["id"].startswith("rec-risky-open-port")]
    check(len(risky) == 1, "one host across two sweeps produces one finding", str(len(risky)))
    if risky:
        detail = risky[0]["detail"]
        for port in ("23/tcp", "445/tcp", "5900/tcp", "111/tcp"):
            check(port in detail, f"the merged finding lists {port}")
        check(risky[0]["id"].endswith("10.0.0.7"), "the id names the address it is about")
        check("10.0.0.0/24" in detail and "10.0.0.7" in detail,
              "the evidence names both ranges that found it")


def test_not_checked_is_reported():
    print("\nhonesty - a check that could not run says so")
    rec = {"site": {"id": "nc"}, "scanned_at": "t",
           "devices": [{"host_id": "gw", "vendor": "mikrotik", "reachable": True}]}
    findings, not_checked = A.run_checks("nc", rec)
    check(any("no config export" in n for n in not_checked),
          "a device with no export on disk is reported as NOT CHECKED, not as clean")
    check(not any(f["id"].startswith("mt-") for f in findings),
          "and it produces no config-based findings either way")

    partial = '### /ip service print detail\n 0   name="telnet" port=23\n'
    _, _, nc = audit("nc-partial", "gw", "mikrotik", partial)
    check(any("mt-input-no-drop" in n for n in nc),
          "a check whose command is missing from the export is named individually")
    check(all("manual" not in n.lower() or "human" in n.lower() for n in nc),
          "manual items are listed as needing a human, not silently dropped")
    check(sum(1 for c in A.CHECKS if c.get("kind") == "manual") ==
          sum(1 for n in nc if n.startswith("needs a human")),
          "every manual check appears in the not-checked list")


def test_catalogue_shape():
    print("\ncatalogue hygiene")
    ids = [c["id"] for c in A.CHECKS]
    check(len(ids) == len(set(ids)), "check ids are unique")
    sev = {"critical", "high", "medium", "low", "info"}
    cat = {"availability", "performance", "capacity", "security", "config-hygiene",
           "lifecycle", "documentation"}
    check(all(c["severity"] in sev for c in A.CHECKS), "every severity is a schema value")
    check(all(c.get("category", "security") in cat for c in A.CHECKS),
          "every category is a schema enum value")
    check(all(c.get("why") and c.get("fix") for c in A.CHECKS),
          "every check explains why it matters and how to fix it")
    check(all(c["kind"] == "manual" or c.get("pattern") for c in A.CHECKS),
          "every automated check has a pattern")
    import re as _re
    broken = [c["id"] for c in A.CHECKS if c.get("pattern") and not _safe(_re.compile, c["pattern"])]
    check(not broken, "every pattern compiles", str(broken))
    check(all(v in A.VENDOR_GUIDE for c in A.CHECKS for v in c["vendors"]),
          "every vendor named by a check has a documented baseline")


def _safe(fn, *a):
    try:
        fn(*a)
        return True
    except Exception:  # noqa: BLE001
        return False


def test_excerpt_is_redacted():
    print("\nevidence excerpts never carry a secret")
    text = 'snmp-server community SuperSecret123 RO\npassword = hunter2\n'
    ex = A.excerpt_for(text, r"(?m)^snmp-server community\s+\S+")
    check("SuperSecret123" not in ex or "redacted" in ex.lower(),
          f"a community string in an excerpt is redacted or absent", ex)
    ex2 = A.excerpt_for(text, r"(?mi)^password")
    check("hunter2" not in ex2, f"a password in an excerpt is redacted", ex2)
    check(len(A.excerpt_for("x" * 5000, "x")) <= 160,
          "an excerpt is one short line, never a config dump")


def test_run_writes_once():
    print("\nrun --write is idempotent")
    site = "write-test"
    d = A.C.site_dir(site)
    (d / "configs").mkdir(parents=True, exist_ok=True)
    (d / "configs" / "gw.security.txt").write_text(MT_VULNERABLE_DETAIL, encoding="utf-8")
    rec_path = d / "scan.json"
    rec_path.write_text(json.dumps({
        "site": {"id": site}, "scanned_at": "t",
        "devices": [{"host_id": "gw", "vendor": "mikrotik", "reachable": True}]}),
        encoding="utf-8")

    class Args:
        pass
    a = Args()
    a.site, a.record, a.dry_run = site, str(rec_path), False
    A.cmd_run(a)
    first = json.loads(rec_path.read_text(encoding="utf-8"))
    A.cmd_run(a)
    second = json.loads(rec_path.read_text(encoding="utf-8"))
    check(len(first["findings"]) > 0, "findings are written into the record")
    check(len(first["findings"]) == len(second["findings"]),
          "running the audit twice does not duplicate findings",
          f"{len(first['findings'])} -> {len(second['findings'])}")
    check(len(first["coverage"]["not_covered"]) == len(second["coverage"]["not_covered"]),
          "and does not duplicate the coverage notes")


def main() -> int:
    print("netwalk hardening catalogue - regression suite")
    test_mikrotik_both_formats()
    test_mikrotik_dump()
    test_dump_cannot_decide_is_not_clean()
    test_command_output_wins_over_a_dump()
    test_unmarked_dump_is_still_a_dump()
    test_dump_line_endings()
    test_disabled_is_not_enabled()
    test_cisco()
    test_linux()
    test_vendor_isolation()
    test_record_checks()
    test_one_finding_per_host_across_sweeps()
    test_not_checked_is_reported()
    test_catalogue_shape()
    test_excerpt_is_redacted()
    test_run_writes_once()
    print(f"\n{PASSED} passed, {len(FAILED)} failed")
    for f in FAILED:
        print(f"  FAILED {f}")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
