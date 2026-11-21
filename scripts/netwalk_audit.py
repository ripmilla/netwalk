#!/usr/bin/env python3
"""Hardening audit for netwalk: vendor best practice, checked in code.

Before this existed, "is anything configured badly?" depended on whether the agent
remembered a paragraph of examples while it was busy reading interface counters. That
is not a check, it is a hope. This module is the checklist as data - every item has an
id, a severity, the evidence that decides it, a fix a technician can apply, and a
reference to where the rule comes from.

Two things make it safe to run against a real customer:

  * **It reads the config export off the disk, not through the conversation.** The
    exports already live in `<site>/configs/` because `netwalk_exec.py --out` put them
    there. This script opens them locally and emits findings; the config text itself
    never enters an agent's context. Excerpts attached to a finding are one line long
    and pass through the same redactor the exec wrapper uses.
  * **It never fails silently.** A check whose evidence is missing is reported as NOT
    CHECKED, by name. A hardening report that quietly skipped half its checks is worse
    than no report, because it reads like a clean bill of health.

Where the rules come from
-------------------------
The vendor's own hardening guidance, plus what actually goes wrong on sites. Each check
names the guidance it comes from, so a customer asking "says who?" gets an answer that
points at the people who built the box rather than at this file.

  netwalk_audit.py guide [--vendor mikrotik] [--format md]   # the checklist itself
  netwalk_audit.py run --site S --record scan.json [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import netwalk_common as C  # noqa: E402
from netwalk_exec import redact_device_secrets  # noqa: E402

VENDOR_GUIDE = {
    "mikrotik": "MikroTik — Securing your router (wiki.mikrotik.com), and RouterOS defaults",
    "cisco": "Cisco Guide to Harden IOS Devices",
    "aruba": "ArubaOS-CX Hardening Guide",
    "hp": "HPE ProCurve / Comware security configuration guide",
    "fortinet": "Fortinet FortiOS Hardening Guide",
    "linux": "Vendor distribution hardening guide (Debian/RHEL security)",
    "windows": "Microsoft Windows Server security baseline",
    "*": "Common network hardening practice",
}

# ---------------------------------------------------------------------------
# The catalogue. This IS the hardening guide - the printed guide is generated
# from it, so the document and the checks cannot drift apart.
#
#   kind = config_present : the pattern matching is the problem
#   kind = config_absent  : the pattern NOT matching is the problem
#   kind = manual         : cannot be decided from a config dump; a human looks
#   cmd                   : scope the search to one command's output block
# ---------------------------------------------------------------------------

CHECKS: list[dict] = [
    # ------------------------------------------------------------- MikroTik
    {
        "id": "mt-telnet-enabled", "vendors": ["mikrotik"], "severity": "high",
        "title": "Telnet is enabled on the router",
        "why": "Telnet carries the admin username and password in clear text. Anyone on a "
               "path between the engineer and the router reads them, and on a flat LAN that "
               "is every host on the network.",
        "fix": "Disable it: /ip service disable telnet. Use SSH, and restrict it with "
               "address= to the management network.",
        "kind": "config_present", "cmd": "/ip service print",
        "pattern": r'(?m)^\s*\d+\s+(?!X[\s])(?:name=")?telnet\b',
        "export_pattern": '(?m)^set telnet\\b(?![^\\n]*\\bdisabled=yes)',
    },
    {
        "id": "mt-ftp-enabled", "vendors": ["mikrotik"], "severity": "medium",
        "title": "The FTP service is enabled",
        "why": "RouterOS FTP is a clear-text file service on the router itself. It is rarely "
               "used deliberately and it accepts the same credentials as the admin account.",
        "fix": "/ip service disable ftp",
        "kind": "config_present", "cmd": "/ip service print",
        "pattern": r'(?m)^\s*\d+\s+(?!X[\s])(?:name=")?ftp\b',
        "export_pattern": '(?m)^set ftp\\b(?![^\\n]*\\bdisabled=yes)',
    },
    {
        "id": "mt-www-plain", "vendors": ["mikrotik"], "severity": "medium",
        "title": "The web interface answers over plain HTTP",
        "why": "The RouterOS web login posts the password over an unencrypted connection. "
               "www-ssl exists and costs nothing but a certificate.",
        "fix": "/ip service disable www and use www-ssl, restricted with address=.",
        "kind": "config_present", "cmd": "/ip service print",
        "pattern": r'(?m)^\s*\d+\s+(?!X[\s])(?:name=")?www\b(?!-ssl)',
        "export_pattern": '(?m)^set www\\b(?!-ssl)(?![^\\n]*\\bdisabled=yes)',
    },
    {
        "id": "mt-api-plain", "vendors": ["mikrotik"], "severity": "medium",
        "title": "The clear-text API service (8728) is enabled",
        "why": "The RouterOS API on 8728 authenticates in clear text. If something automates "
               "this router it should be doing it over api-ssl (8729).",
        "fix": "/ip service disable api, and use api-ssl if an integration needs it.",
        "kind": "config_present", "cmd": "/ip service print",
        "pattern": r'(?m)^\s*\d+\s+(?!X[\s])(?:name=")?api\b(?!-ssl)',
        "export_pattern": '(?m)^set api\\b(?!-ssl)(?![^\\n]*\\bdisabled=yes)',
    },
    {
        "id": "mt-input-no-drop", "vendors": ["mikrotik"], "severity": "critical",
        "title": "The firewall input chain has no drop rule at all",
        "why": "RouterOS ends a chain with an implicit ACCEPT. With no catch-all drop in the "
               "input chain, every management service the router runs answers on every "
               "address it holds, including its public ones. This has been found in the "
               "field: Winbox, the web interface, SNMP and IPsec all answering from the "
               "internet on a router whose owner believed it was firewalled.",
        "fix": "End the input chain with a catch-all: /ip firewall filter add chain=input "
               "action=drop, after the rules that accept established/related traffic and "
               "management from the trusted network. Add it last, and test from a console "
               "session you cannot lock yourself out of.",
        "kind": "config_absent", "cmd": "/ip firewall filter print",
        "pattern": r"chain=input[^\n]*action=(drop|reject)",
        "export_pattern": '(?m)(chain=input[^\\n]*action=(drop|reject)|action=(drop|reject)[^\\n]*chain=input)',
    },
    {
        "id": "mt-snmp-v1v2", "vendors": ["mikrotik"], "severity": "high",
        "title": "SNMP v1/v2c is in use",
        "why": "v1 and v2c authenticate with a community string sent in clear text, and it is "
               "usually 'public'. Anyone who can reach the port can read the whole device "
               "inventory, interface list and traffic counters.",
        "fix": "Move to SNMPv3 with authPriv, or restrict the community to the monitoring "
               "host's address and treat the string as a password.",
        "kind": "config_present", "cmd": "/snmp community print",
        "pattern": r"(?im)^\s*\d+\s+\S*\s*(public|private)\b|authentication-protocol=\s*$",
        "export_pattern": '\\bname=(public|private)\\b',
    },
    {
        "id": "mt-romon-enabled", "vendors": ["mikrotik"], "severity": "medium",
        "title": "RoMON is enabled",
        "why": "RoMON gives layer-2 management access to every RoMON-speaking MikroTik in the "
               "broadcast domain, bypassing IP firewalling entirely. Convenient for the "
               "engineer, equally convenient for anyone who plugs into a switch port.",
        "fix": "Disable it when it is not actively in use: /tool romon set enabled=no. If it "
               "is needed, set a RoMON secret and restrict the ports it runs on.",
        "kind": "config_present", "cmd": "/tool romon print",
        "pattern": r"(?im)^\s*enabled:\s*yes",
        "export_pattern": '\\benabled=yes\\b',
    },
    {
        "id": "mt-mac-server-all", "vendors": ["mikrotik"], "severity": "medium",
        "title": "MAC-Telnet / MAC-Winbox is available on all interfaces",
        "why": "MAC server access needs no IP address and ignores IP firewall rules. Left on "
               "'all', an unauthenticated layer-2 neighbour - including one on the WAN side "
               "of a bridged link - can reach the login prompt.",
        "fix": "Restrict to a management interface list: /tool mac-server set "
               "allowed-interface-list=MGMT, same for mac-winbox.",
        "kind": "config_present", "cmd": "/tool mac-server print",
        "pattern": r"(?im)allowed-interface-list:\s*(all|\*all)",
        "export_pattern": 'allowed-interface-list=(all|\\*all)',
    },
    {
        "id": "mt-discovery-all", "vendors": ["mikrotik"], "severity": "low",
        "title": "Neighbour discovery runs on every interface, including the WAN",
        "why": "MNDP/CDP/LLDP announcements on an internet-facing interface tell anyone "
               "listening the model, the RouterOS version and the identity of the device.",
        "fix": "/ip neighbor discovery-settings set discover-interface-list=LAN",
        "kind": "config_present", "cmd": "/ip neighbor discovery-settings print",
        "pattern": r"(?im)discover-interface-list:\s*(all|\*all)",
        "export_pattern": 'discover-interface-list=(all|\\*all)',
    },
    {
        "id": "mt-bandwidth-server", "vendors": ["mikrotik"], "severity": "low",
        "title": "The bandwidth-test server is enabled",
        "why": "It is a service anyone with credentials can point at the router to saturate "
               "its CPU. It is on by default and almost never used in production.",
        "fix": "/tool bandwidth-server set enabled=no",
        "kind": "config_present", "cmd": "/tool bandwidth-server print",
        "pattern": r"(?im)^\s*enabled:\s*yes",
        "export_pattern": '\\benabled=yes\\b',
    },
    {
        "id": "mt-socks-upnp", "vendors": ["mikrotik"], "severity": "medium",
        "title": "SOCKS proxy or UPnP is enabled",
        "why": "An enabled SOCKS proxy turns the router into an open relay if it is not "
               "access-listed. UPnP lets any host on the LAN open a hole through the NAT "
               "without asking anybody.",
        "fix": "/ip socks set enabled=no and /ip upnp set enabled=no unless something "
               "genuinely needs them, in which case restrict them.",
        "kind": "config_present", "cmd": "/ip socks print",
        "pattern": r"(?im)^\s*enabled:\s*yes",
        "export_pattern": '\\benabled=yes\\b',
    },
    {
        "id": "mt-dns-remote", "vendors": ["mikrotik"], "severity": "high",
        "confidence": "suspected",
        "title": "The router answers DNS queries from anywhere",
        "why": "allow-remote-requests=yes with no input firewall makes the router an open "
               "resolver: usable for DNS amplification attacks against third parties, which "
               "is how a small site ends up on a blocklist. This setting alone does not "
               "prove exposure: it says the resolver will answer, not that anything can "
               "reach it. CHECK /ip firewall raw AND filter for a drop of port 53 from the "
               "WAN before reporting this, and downgrade or drop the finding if one exists - "
               "at a real site the raw table already dropped UDP/53 and only TCP/53 was "
               "reachable, which is a different, smaller finding.",
        "fix": "Keep allow-remote-requests=yes only if the LAN uses the router for DNS, and "
               "make sure the input chain drops UDP/TCP 53 from the WAN.",
        "kind": "config_present", "cmd": "/ip dns print",
        "pattern": r"(?im)allow-remote-requests:\s*yes",
        "export_pattern": 'allow-remote-requests=yes',
    },
    {
        "id": "mt-no-ntp", "vendors": ["mikrotik"], "severity": "low", "category": "config-hygiene",
        "title": "No NTP client is configured",
        "why": "Without synchronised time every log line and every certificate check is "
               "unreliable, and correlating an incident across two devices becomes guesswork.",
        "fix": "/system ntp client set enabled=yes servers=<two reachable servers>",
        "kind": "config_absent", "cmd": "/system ntp client print",
        "pattern": r"(?im)^\s*enabled:\s*yes",
        "export_pattern": '\\benabled=yes\\b',
    },
    {
        "id": "mt-no-remote-logging", "vendors": ["mikrotik"], "severity": "medium",
        "category": "config-hygiene",
        "title": "Logs are not sent anywhere off the device",
        "why": "RouterOS keeps its log in RAM by default. A reboot - or anyone who caused one "
               "- erases the only record of what happened.",
        "fix": "/system logging action add name=remote target=remote remote=<syslog host>, "
               "then point the topics that matter at it.",
        "kind": "config_absent", "cmd": "/system logging action print",
        "pattern": r"(?im)\bremote\b",
        "export_pattern": '\\bremote\\b',
    },
    {
        "id": "mt-default-admin", "vendors": ["mikrotik"], "severity": "high",
        "title": "The default 'admin' account still exists",
        "why": "Every brute-force script starts with admin. A named account per engineer also "
               "means the log says who did something, not just that someone did.",
        "fix": "Create a named full-access user, verify you can log in with it, then remove or "
               "disable admin.",
        "kind": "config_present", "cmd": "/user print",
        "pattern": r'(?m)^\s*\d+\s+(?:X\s+)?(?:name=")?admin\b',
    },

    # ---------------------------------------------------------------- Cisco
    {
        "id": "cis-no-password-encryption", "vendors": ["cisco"], "severity": "medium",
        "title": "service password-encryption is not enabled",
        "why": "Without it, passwords in the running-config are stored and displayed in clear "
               "text - and a config gets copied into tickets, backups and emails.",
        "fix": "conf t; service password-encryption. Note this is obfuscation (type 7), not "
               "encryption; it stops shoulder-surfing, not an attacker with the file.",
        "kind": "config_absent", "cmd": "show running-config",
        "pattern": r"(?m)^service password-encryption",
    },
    {
        "id": "cis-enable-password", "vendors": ["cisco"], "severity": "high",
        "title": "'enable password' is used instead of 'enable secret'",
        "why": "enable password is stored reversibly. enable secret is hashed. Any config that "
               "leaks hands over privileged access with the first one.",
        "fix": "conf t; enable secret <strong value>; no enable password",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?m)^enable password\b",
    },
    {
        "id": "cis-vty-telnet", "vendors": ["cisco"], "severity": "high",
        "title": "The VTY lines accept telnet",
        "why": "transport input telnet or all means the device accepts clear-text admin "
               "sessions, no matter how good the password is.",
        "fix": "conf t; line vty 0 15; transport input ssh",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?m)^\s*transport input (telnet|all)\b",
    },
    {
        "id": "cis-http-server", "vendors": ["cisco"], "severity": "medium",
        "title": "The HTTP management server is enabled",
        "why": "The IOS HTTP server has a long CVE history and authenticates in clear text. "
               "Very few sites use it deliberately.",
        "fix": "conf t; no ip http server. Keep ip http secure-server only if something needs it.",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?m)^ip http server\b",
    },
    {
        "id": "cis-snmp-default-community", "vendors": ["cisco"], "severity": "high",
        "title": "A default or guessable SNMP community is configured",
        "why": "'public' and 'private' are the first two strings any scanner tries. RW private "
               "is not a read risk, it is a device takeover.",
        "fix": "Remove them, move to SNMPv3, and access-list whatever remains to the "
               "monitoring host.",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?mi)^snmp-server community\s+(public|private)\b",
    },
    {
        "id": "cis-no-aaa", "vendors": ["cisco"], "severity": "medium",
        "title": "AAA is not enabled",
        "why": "Without aaa new-model the device falls back to line passwords, which are "
               "shared, unattributable and survive staff changes.",
        "fix": "conf t; aaa new-model, with local fallback configured before you commit it.",
        "kind": "config_absent", "cmd": "show running-config",
        "pattern": r"(?m)^aaa new-model",
    },
    {
        "id": "cis-no-logging-host", "vendors": ["cisco"], "severity": "medium",
        "category": "config-hygiene",
        "title": "No syslog destination is configured",
        "why": "The local buffer is small and disappears on reload. Nothing to correlate after "
               "an incident.",
        "fix": "conf t; logging host <syslog>; service timestamps log datetime msec localtime",
        "kind": "config_absent", "cmd": "show running-config",
        "pattern": r"(?m)^logging (host )?\d+\.\d+\.\d+\.\d+",
    },
    {
        "id": "cis-no-bpduguard", "vendors": ["cisco"], "severity": "medium",
        "category": "availability",
        "title": "BPDU guard is not enabled by default on access ports",
        "why": "One person plugging a cheap switch or a looped patch lead into a wall port can "
               "take the spanning tree - and the site - down. BPDU guard turns that into one "
               "dead port instead.",
        "fix": "conf t; spanning-tree portfast bpduguard default (and portfast on access ports)",
        "kind": "config_absent", "cmd": "show running-config",
        "pattern": r"(?m)^spanning-tree portfast (edge )?bpduguard default",
    },
    {
        "id": "cis-no-dhcp-snooping", "vendors": ["cisco"], "severity": "low",
        "title": "DHCP snooping is not configured",
        "why": "Without it any host can answer DHCP and become the default gateway for the "
               "VLAN. It is also the table Dynamic ARP Inspection depends on.",
        "fix": "conf t; ip dhcp snooping; ip dhcp snooping vlan <list>; trust the uplinks.",
        "kind": "config_absent", "cmd": "show running-config",
        "pattern": r"(?m)^ip dhcp snooping",
    },
    {
        "id": "cis-vty-no-timeout", "vendors": ["cisco"], "severity": "low",
        "title": "A VTY line has its idle timeout disabled",
        "why": "exec-timeout 0 0 leaves an authenticated session open forever - including the "
               "one on the laptop somebody left in a meeting room.",
        "fix": "conf t; line vty 0 15; exec-timeout 10 0",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?m)^\s*exec-timeout 0 0\b",
    },

    # ---------------------------------------------------------------- Linux
    {
        "id": "lnx-ssh-root-login", "vendors": ["linux"], "severity": "high",
        "title": "sshd permits direct root login",
        "why": "root is the one account name an attacker never has to guess, and a root "
               "session leaves no record of which person was at the keyboard.",
        "fix": "PermitRootLogin no in /etc/ssh/sshd_config, after confirming an admin account "
               "with sudo works.",
        "kind": "config_present", "cmd": "cat /etc/ssh/sshd_config",
        "pattern": r"(?mi)^\s*PermitRootLogin\s+(yes|without-password|prohibit-password)",
    },
    {
        "id": "lnx-ssh-password-auth", "vendors": ["linux"], "severity": "medium",
        "title": "sshd accepts password authentication",
        "why": "Password auth is what makes a box worth brute-forcing. Key auth removes the "
               "entire category.",
        "fix": "PasswordAuthentication no, once every account that needs access has a key "
               "installed and tested.",
        "kind": "config_present", "cmd": "cat /etc/ssh/sshd_config",
        "pattern": r"(?mi)^\s*PasswordAuthentication\s+yes",
    },
    {
        "id": "lnx-empty-firewall", "vendors": ["linux"], "severity": "medium",
        "title": "The host firewall has no rules",
        "why": "Every listening socket on the box is reachable from every host that can route "
               "to it. On a flat LAN that is everything, including the guest Wi-Fi.",
        "fix": "Apply a default-deny inbound policy with explicit allows, via nftables, ufw or "
               "firewalld - whichever the distribution already uses.",
        "kind": "config_absent", "cmd": "iptables -S",
        "pattern": r"(?m)^-A\s+INPUT",
    },
    {
        "id": "lnx-clear-text-services", "vendors": ["linux"], "severity": "high",
        "title": "A clear-text service is listening",
        "why": "telnet, rsh, ftp and tftp hand credentials and data to anyone on the path. "
               "Their encrypted replacements have existed for thirty years.",
        "fix": "Disable the unit and remove the package. Use ssh/sftp instead.",
        "kind": "config_present", "cmd": "ss -tulpn",
        "pattern": r"(?m):(23|21|512|513|514|69)\s",
    },
    {
        "id": "lnx-nopasswd-sudo", "vendors": ["linux"], "severity": "medium",
        "title": "sudo is configured with NOPASSWD",
        "why": "Any process that lands as that user is already root. It converts a low-value "
               "foothold into a full compromise with no extra step.",
        "fix": "Remove NOPASSWD, or narrow it to the single command that genuinely needs it.",
        "kind": "config_present", "cmd": "cat /etc/sudoers",
        "pattern": r"(?m)NOPASSWD",
    },

    # ------------------------------------------------------------- Fortinet
    {
        "id": "fg-admin-http", "vendors": ["fortinet"], "severity": "high",
        "title": "HTTP or telnet administrative access is allowed on an interface",
        "why": "allowaccess including http or telnet means the management interface "
               "authenticates in clear text on that interface.",
        "fix": "config system interface; set allowaccess ping https ssh - and drop http and "
               "telnet everywhere, especially on the WAN interface.",
        "kind": "config_present", "cmd": "show system interface",
        "pattern": r"(?m)set allowaccess[^\n]*\b(http|telnet)\b",
    },
    {
        "id": "fg-no-password-policy", "vendors": ["fortinet"], "severity": "low",
        "title": "No administrator password policy is set",
        "why": "Without one, an admin account can keep a four-character password indefinitely.",
        "fix": "config system password-policy; set status enable with a minimum length and "
               "an expiry that people will actually follow.",
        "kind": "config_absent", "cmd": "show system password-policy",
        "pattern": r"(?m)set status enable",
    },

    # ------------------------------------------------------------ Aruba / HP
    {
        "id": "arb-telnet-enabled", "vendors": ["aruba", "hp"], "severity": "high",
        "title": "The telnet server is enabled on the switch",
        "why": "Clear-text admin access to a switch that sees every VLAN on the site.",
        "fix": "no telnet-server (ArubaOS-CX) / no telnet-server (ProCurve), and confirm SSH "
               "works before you disable it.",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?m)^\s*telnet-server\b(?!\s+vrf\s+none)",
    },
    {
        "id": "arb-snmp-default-community", "vendors": ["aruba", "hp"], "severity": "high",
        "title": "A default SNMP community is configured on the switch",
        "why": "public/private on a switch exposes the full port, VLAN and MAC picture of the "
               "site to anyone who can reach the management address.",
        "fix": "Remove the default community, move to SNMPv3, restrict by source address.",
        "kind": "config_present", "cmd": "show running-config",
        "pattern": r"(?mi)^\s*snmp-server (community|vrf \S+ community)\s+\"?(public|private)\b",
    },

    # ------------------------------------------------------ manual, everywhere
    {
        "id": "man-firmware-eol", "vendors": ["*"], "severity": "medium",
        "category": "lifecycle", "kind": "manual",
        "title": "Firmware version against vendor support and known CVEs",
        "why": "netwalk records the version but carries no CVE or end-of-support database, and "
               "guessing at one would be worse than saying nothing. This has to be looked up.",
        "fix": "Check each recorded os_version against the vendor's security advisories and "
               "end-of-support dates, and raise a finding per device that is behind.",
    },
    {
        "id": "man-physical-access", "vendors": ["*"], "severity": "medium",
        "category": "security", "kind": "manual",
        "title": "Physical access to network equipment",
        "why": "A switch in an unlocked cupboard or under a reception desk defeats every "
               "control in this list. No command reveals it.",
        "fix": "Walk the site: are the racks locked, are unused wall ports patched through, is "
               "the router reachable by a visitor?",
    },
    {
        "id": "man-backup-restore", "vendors": ["*"], "severity": "medium",
        "category": "availability", "kind": "manual",
        "title": "Configuration backups exist and have been restored at least once",
        "why": "An export sitting on the device is not a backup, and a backup nobody has ever "
               "restored is a hypothesis.",
        "fix": "Confirm where configs are backed up, how often, and when a restore was last "
               "actually tested.",
    },
    {
        "id": "man-account-review", "vendors": ["*"], "severity": "medium", "kind": "manual",
        "title": "Who has an account, and should they still",
        "why": "netwalk can list accounts but cannot know that the contractor from two years "
               "ago has left. Shared accounts also look perfectly healthy in a config.",
        "fix": "Go through the account list with the owner: name each one, remove the ones "
               "nobody claims, and replace shared logins with named ones.",
    },
]


# ---------------------------------------------------------------------------
# Record checks: decided from structured fields, not from text. These carry
# confidence "confirmed" because they read a value, not a pattern in a dump.
# ---------------------------------------------------------------------------

WEAK_WIFI = {"open", "wep", "wpa-personal"}

RISKY_PORTS = {
    23: ("telnet", "high"), 21: ("ftp", "medium"), 445: ("smb", "high"),
    3389: ("rdp", "high"), 5900: ("vnc", "high"), 6379: ("redis", "high"),
    27017: ("mongodb", "high"), 1433: ("mssql", "medium"), 3306: ("mysql", "medium"),
    5432: ("postgresql", "medium"), 9200: ("elasticsearch", "high"),
    10000: ("webmin", "high"), 8291: ("winbox", "medium"), 8728: ("mikrotik-api", "medium"),
    7547: ("tr-069", "high"), 873: ("rsync", "medium"), 111: ("rpcbind", "medium"),
}


def _sortable_ip(a: str):
    import ipaddress as _ip  # noqa: PLC0415
    try:
        x = _ip.ip_address(a)
        return (0, x.version, x.packed)
    except ValueError:
        return (1, 0, a.encode())


def rc_mgmt_on_wan(rec: dict) -> list[dict]:
    out = []
    for d in rec.get("devices") or []:
        wan = (d.get("mgmt_exposure") or {}).get("reachable_from_wan") or []
        if wan:
            out.append(_finding(
                f"rec-mgmt-on-wan@{d.get('host_id')}", "critical", "security", d.get("host_id"),
                "Management services answer on a public address",
                f"{', '.join(wan)} answered on a WAN-facing address of this device. Anything "
                f"reachable from the internet is under continuous automated attack; a "
                f"management service there is a matter of when, not whether.",
                [{"source": "mgmt_exposure.reachable_from_wan", "excerpt": ", ".join(wan)}],
                "Restrict management to the inside interfaces and the management network, and "
                "put a catch-all drop at the end of the input chain. If remote access is "
                "genuinely needed, put it behind a VPN rather than on a public port.",
                "confirmed", public_safe=False,
                refs={"vendor": VENDOR_GUIDE.get(d.get("vendor"), VENDOR_GUIDE["*"])}))
    return out


def rc_weak_wifi(rec: dict) -> list[dict]:
    out = []
    for d in rec.get("devices") or []:
        for w in d.get("wireless_networks") or []:
            sec = (w.get("security") or "unknown").lower()
            if sec in WEAK_WIFI:
                sev = "critical" if sec in ("open", "wep") else "medium"
                out.append(_finding(
                    f"rec-weak-wifi@{d.get('host_id')}:{w.get('ssid')}", sev, "security",
                    d.get("host_id"),
                    f"SSID '{w.get('ssid')}' uses {sec} security",
                    {"open": "An open SSID puts every client's traffic in the air unencrypted "
                             "and gives anyone in range a place on the network.",
                     "wep": "WEP is broken. Recovering the key takes minutes with tooling that "
                            "has been public since 2007.",
                     "wpa-personal": "WPA1/TKIP is deprecated and should not still be in "
                                     "service; it also caps the whole SSID at legacy rates."
                     }[sec],
                    [{"source": "wireless_networks[].security", "excerpt": f"{w.get('ssid')}: {sec}"}],
                    "Move the SSID to WPA2-Enterprise where there is a directory to "
                    "authenticate against, or WPA2/3-Personal with a long passphrase where "
                    "there is not. If the open SSID is a deliberate guest network, put it on "
                    "its own VLAN with client isolation and a rate limit.",
                    "confirmed", public_safe=False,
                    refs={"vendor": "Wi-Fi Alliance / vendor WLAN hardening guidance"}))
            if w.get("guest") and w.get("client_isolation") is False:
                out.append(_finding(
                    f"rec-guest-no-isolation@{d.get('host_id')}:{w.get('ssid')}", "medium",
                    "security", d.get("host_id"),
                    f"Guest SSID '{w.get('ssid')}' has no client isolation",
                    "Guests can reach each other directly. One compromised laptop in the "
                    "waiting room can attack every other guest device on the same SSID.",
                    [{"source": "wireless_networks[].client_isolation", "excerpt": "false"}],
                    "Enable client/station isolation on the guest SSID and confirm the guest "
                    "VLAN cannot route to the internal networks.",
                    "confirmed", public_safe=False,
                    refs={"vendor": "Vendor WLAN hardening guidance"}))
    return out


def rc_risky_open_ports(rec: dict) -> list[dict]:
    """Findings straight out of the authorised sweep - what is listening, and why it matters.

    A host normally appears in more than one sweep: the host sweep probes a handful of
    ports to decide it is alive, and a port scan afterwards looks properly. Emitting one
    finding per sweep put the same address in a customer report twice, at two severities,
    each listing a different subset of the same problem. Ports are merged per address, and
    the ranges that produced them are named in the evidence.
    """
    merged: dict[str, dict] = {}
    for s in rec.get("sweeps") or []:
        for h in s.get("hosts") or []:
            e = merged.setdefault(h["ip"], {"ports": set(), "ranges": []})
            e["ports"].update(h.get("open_ports") or [])
            if s.get("range") and s["range"] not in e["ranges"]:
                e["ranges"].append(s["range"])

    out = []
    for ip in sorted(merged, key=lambda a: _sortable_ip(a)):
        e = merged[ip]
        risky = [(p, RISKY_PORTS[p]) for p in sorted(e["ports"]) if p in RISKY_PORTS]
        if not risky:
            continue
        worst = "high" if any(sev == "high" for _, (_, sev) in risky) else "medium"
        listed = ", ".join(f"{p}/tcp {name}" for p, (name, _) in risky)
        s = {"range": ", ".join(e["ranges"])}
        h = {"ip": ip}
        if True:
            out.append(_finding(
                f"rec-risky-open-port@{ip}", worst, "security", None,
                f"{h['ip']} is listening on {len(risky)} service(s) that should not be open "
                f"on a general network",
                f"The authorised sweep of {s.get('range')} found {listed} answering on "
                f"{h['ip']}. Clear-text admin protocols and databases on a user-accessible "
                f"VLAN are the shortest path from a compromised laptop to everything else.",
                [{"source": f"sweep {s.get('range')}", "excerpt": f"{h['ip']}: {listed}"}],
                "Confirm what this host is, then either restrict the service to a management "
                "network, put it behind authentication it does not currently have, or turn it "
                "off. Databases in particular have no business listening beyond their "
                "application server.",
                "confirmed", public_safe=False,
                refs={"vendor": VENDOR_GUIDE["*"]}))
    return out


def rc_unidentified_hosts(rec: dict) -> list[dict]:
    unknown = []
    for s in rec.get("sweeps") or []:
        unknown += [h["ip"] for h in (s.get("hosts") or []) if not h.get("in_record")]
    if not unknown:
        return []
    return [_finding(
        "rec-unidentified-host", "medium", "documentation", None,
        f"{len(unknown)} address(es) on the network could not be identified",
        "These answered a sweep of an authorised range but are not in the device inventory "
        "and the site owner has not named them. An unidentified device is not necessarily a "
        "problem, but nobody being able to say what it is, is.",
        [{"source": "sweeps[].hosts", "excerpt": ", ".join(sorted(set(unknown))[:12])}],
        "Trace each address to a physical port and a person. Until that is done they are on "
        "the network with nobody accountable for them.",
        "confirmed", public_safe=False,
        refs={"vendor": VENDOR_GUIDE["*"]})]


RECORD_CHECKS = [rc_mgmt_on_wan, rc_weak_wifi, rc_risky_open_ports, rc_unidentified_hosts]


# ---------------------------------------------------------------------------
# Machinery
# ---------------------------------------------------------------------------

BLOCK_RE = re.compile(r"^### (.+)$", re.MULTILINE)
# The command that produces a RouterOS configuration dump rather than command output.
EXPORT_MARK_RE = re.compile(r"^/export(\s|$)")
# `/ip service print` prints the `/ip service` section of a dump.
CMD_SECTION_RE = re.compile(r"^(.*?)\s+print(?:\s+detail)?$")
# A dump that nobody marked still has to be recognisable. Its sections are paths
# at the left margin and the settings under them are `set`/`add` lines. Both
# have to be there: one on its own is too weak to call a file a dump.
DUMP_SECTION_RE = re.compile(r"^/\S", re.MULTILINE)
DUMP_ENTRY_RE = re.compile(r"^(set|add)\s+\S", re.MULTILINE)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def die(msg: str, code: int = 1):
    print(f"netwalk_audit: {msg}", file=sys.stderr)
    raise SystemExit(code)


def split_blocks(text: str) -> dict[str, str] | None:
    """`### cmd` sections written by `netwalk_exec.py run --out`. None if unmarked."""
    marks = list(BLOCK_RE.finditer(text))
    if not marks:
        return None
    out = {}
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out[m.group(1).strip()] = text[m.end():end]
    return out


def scope(text: str, cmd: str | None) -> tuple[str | None, bool]:
    """The slice of `text` a check should look at, and whether it came from a dump.

    None for the text means the evidence is not present. The flag says where the
    text came from: a check written against the output of a command has a
    different pattern for the same setting in a configuration dump.
    """
    if not cmd:
        return text, False
    blocks = split_blocks(text)
    if blocks is not None:
        for name, body in blocks.items():
            if name.startswith(cmd) or cmd in name:
                return body, False
    sec = export_section(text, cmd)
    if sec is not None:
        return sec, True
    if blocks is None and not export_body(text):
        return text, False        # not a dump: the whole file is what the command printed
    return None, False


def looks_like_dump(text: str) -> bool:
    """True if the text is a RouterOS configuration dump with no marker above it."""
    return bool(DUMP_SECTION_RE.search(text) and DUMP_ENTRY_RE.search(text))


def export_body(text: str) -> str | None:
    """The configuration dump in `text`, if there is one.

    `netwalk_exec.py run --out` records the command that produced a file above its
    contents. A file whose command was `/export verbose` holds a RouterOS
    configuration dump rather than the output of one command, and it is organised
    by subsystem - not by command. A dump copied into the directory by hand has no
    marker above it, and is recognised by its shape instead.
    """
    blocks = split_blocks(text)
    if blocks is not None:
        for name, body in blocks.items():
            if EXPORT_MARK_RE.match(name):
                return body
        return None
    if looks_like_dump(text):
        return text
    return None


def export_sections(text: str) -> dict[str, str]:
    """The sections of a configuration dump, keyed by the path they belong to.

    A dump lists `/ip service`, then the settings under it, then `/user`, then the
    settings under that. A check scoped to a command needs the section that
    command prints: a setting that belongs to another subsystem is not evidence
    about this one - `!remote-address` in a queue rule says nothing about
    whether a remote log target is configured.
    """
    body = export_body(text)
    if body is None:
        return {}
    sections: dict[str, list[str]] = {}
    current = None
    # RouterOS wraps a long setting across lines with a trailing backslash. The
    # settings of one entry live on one logical line, and a pattern that looks for
    # `disabled=yes` has to see it next to the entry it belongs to. RouterOS
    # terminates its lines with CRLF, so the fold has to allow for the \r.
    for raw in re.sub(r"\\[ \t]*\r?\n[ \t]*", " ", body).splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("/"):
            current = line
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {path: "\n".join(lines) for path, lines in sections.items()}


def export_section(text: str, cmd: str | None) -> str | None:
    """The part of a configuration dump that `cmd` would have printed."""
    if not cmd:
        return None
    m = CMD_SECTION_RE.match(cmd)
    if not m:
        return None
    return export_sections(text).get(m.group(1))


def config_text(site: str, dev: dict) -> tuple[str, list[str]]:
    """Read this device's exports off the disk. The text never leaves this process."""
    cfgdir = C.site_dir(site) / "configs"
    seen, parts, names = set(), [], []
    candidates = []
    if dev.get("config_export_path"):
        candidates.append(cfgdir / Path(dev["config_export_path"]).name)
    host = dev.get("host_id") or ""
    if host and cfgdir.is_dir():
        candidates += sorted(cfgdir.glob(f"{host}*"))
    for p in candidates:
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        try:
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
            names.append(p.name)
        except OSError:
            continue
    return "\n".join(parts), names


def excerpt_for(text: str, pattern: str) -> str:
    """One redacted line of evidence. Never more - this ends up in a document."""
    m = re.search(pattern, text)
    if not m:
        return ""
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.end())
    line = text[start:end if end != -1 else len(text)].strip()
    line, _ = redact_device_secrets(line)
    return line[:160]


def _finding(cid, severity, category, host_id, title, detail, evidence, rec_fix,
             confidence, public_safe=False, refs=None) -> dict:
    f = {
        "id": cid, "severity": severity, "category": category, "title": title,
        "detail": detail, "evidence": [{**e, "observed_at": now_iso()} for e in evidence],
        "confidence": confidence, "recommendation": rec_fix, "public_safe": public_safe,
    }
    if host_id:
        f["host_id"] = host_id
    if refs:
        f["references"] = [v for v in (refs.get("vendor"),) if v]
    return f


def checks_for(vendor: str | None) -> list[dict]:
    v = (vendor or "unknown").lower()
    return [c for c in CHECKS if "*" in c["vendors"] or v in c["vendors"]]


def run_checks(site: str, rec: dict) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    not_checked: list[str] = []

    for dev in rec.get("devices") or []:
        if not dev.get("reachable"):
            continue
        vendor = (dev.get("vendor") or "").lower()
        host = dev.get("host_id") or "?"
        text, files = config_text(site, dev)
        applicable = [c for c in checks_for(vendor) if c.get("kind") != "manual"]
        if not text:
            if applicable:
                not_checked.append(f"{host}: no config export on disk, so {len(applicable)} "
                                   f"{vendor or 'vendor'} check(s) could not run")
            continue
        for c in applicable:
            body, from_dump = scope(text, c.get("cmd"))
            if body is None:
                if export_body(text):
                    not_checked.append(f"{host}: {c['id']} needs the output of "
                                       f"`{c['cmd']}`, which is not in the configuration "
                                       f"dump in {', '.join(files)}")
                else:
                    not_checked.append(f"{host}: {c['id']} needs the output of "
                                       f"`{c['cmd']}`, which is not in {', '.join(files)}")
                continue
            pattern = c.get("export_pattern") if from_dump else c["pattern"]
            if not pattern:
                not_checked.append(f"{host}: {c['id']} cannot be decided from a "
                                   f"configuration dump - it reads the output of "
                                   f"`{c['cmd']}`, and a dump is not that shape")
                continue
            hit = re.search(pattern, body)
            bad = bool(hit) if c["kind"] == "config_present" else not hit
            if not bad:
                continue
            ev = [{"source": c.get("cmd") or (files[0] if files else "config export"),
                   "excerpt": excerpt_for(body, pattern) if c["kind"] == "config_present"
                   else f"no line matching /{pattern}/ in this output"}]
            findings.append(_finding(
                f"{c['id']}@{host}", c["severity"], c.get("category", "security"), host,
                c["title"], c["why"], ev, c["fix"],
                c.get("confidence") or
                ("confirmed" if c["kind"] == "config_present" else "suspected"),
                public_safe=False,
                refs={"vendor": VENDOR_GUIDE.get(vendor, VENDOR_GUIDE["*"])}))

    for fn in RECORD_CHECKS:
        findings += fn(rec)

    not_checked += [f"needs a human, not a command: {c['title']}"
                    for c in CHECKS if c.get("kind") == "manual"]
    return findings, not_checked


# ------------------------------------------------------------------ commands

def cmd_guide(args) -> int:
    sel = [c for c in CHECKS
           if not args.vendor or "*" in c["vendors"] or args.vendor.lower() in c["vendors"]]
    if args.format == "md":
        print("# netwalk hardening checklist\n")
        by_vendor: dict[str, list] = {}
        for c in sel:
            for v in c["vendors"]:
                by_vendor.setdefault(v, []).append(c)
        for v in sorted(by_vendor):
            print(f"\n## {v}\n\n_Baseline: {VENDOR_GUIDE.get(v, VENDOR_GUIDE['*'])}_\n")
            print("| id | severity | check | how it is decided |")
            print("|---|---|---|---|")
            for c in by_vendor[v]:
                how = {"config_present": f"`{c.get('cmd') or 'config'}` matches",
                       "config_absent": f"`{c.get('cmd') or 'config'}` does NOT match",
                       "manual": "**a human looks — not automated**"}[c["kind"]]
                print(f"| `{c['id']}` | {c['severity']} | {c['title']} | {how} |")
        return 0

    print(f"{len(sel)} check(s){' for ' + args.vendor if args.vendor else ''}\n")
    for c in sel:
        auto = "MANUAL" if c["kind"] == "manual" else c["kind"]
        print(f"[{c['severity']:>8}] {c['id']:<28} {c['title']}")
        print(f"           vendors: {', '.join(c['vendors'])}   decided by: {auto}"
              f"{'  via ' + c['cmd'] if c.get('cmd') else ''}")
        print(f"           why : {c['why']}")
        print(f"           fix : {c['fix']}")
        for v in c["vendors"]:
            print(f"           ref : {VENDOR_GUIDE.get(v, VENDOR_GUIDE['*'])}")
        print()
    return 0


def cmd_run(args) -> int:
    rec_path = Path(args.record).expanduser()
    try:
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        die(f"cannot read the scan record {rec_path}: {e}", 3)

    findings, not_checked = run_checks(args.site, rec)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), f.get("host_id") or ""))

    print(f"{len(findings)} finding(s) from {len(CHECKS)} catalogue check(s)\n")
    for f in findings:
        print(f"  [{f['severity']:>8}] {f.get('host_id') or '-':<14} {f['title']}")
    if not_checked:
        print(f"\nNOT CHECKED ({len(not_checked)}) - say so in the report rather than letting "
              f"it read as a clean result:")
        for n in not_checked:
            print(f"  - {n}")

    if args.dry_run:
        print("\n--dry-run: the record was not modified")
        return 0

    existing = rec.setdefault("findings", [])
    have = {f.get("id") for f in existing}
    added = [f for f in findings if f["id"] not in have]
    existing += added
    cov = rec.setdefault("coverage", {}).setdefault("not_covered", [])
    for n in not_checked:
        note = f"hardening check not run - {n}"
        if note not in cov:
            cov.append(note)
    rec_path.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")
    print(f"\n{len(added)} finding(s) added to {rec_path} "
          f"({len(findings) - len(added)} already present)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="netwalk_audit.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("guide", help="print the hardening checklist itself")
    g.add_argument("--vendor")
    g.add_argument("--format", choices=["text", "md"], default="text")
    g.set_defaults(func=cmd_guide)

    r = sub.add_parser("run", help="check a scanned site against the catalogue")
    r.add_argument("--site", required=True)
    r.add_argument("--record", required=True)
    r.add_argument("--dry-run", action="store_true", help="print findings, change nothing")
    r.set_defaults(func=cmd_run)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
