"""
Detection rules, written as data.

Each rule matches a single event when the event ID is in `event_ids` and
every (field, regex) pair in `match` matches (case-insensitive). The `story`
template turns a hit into a plain-English sentence for the timeline; any
event field can be used as a placeholder, e.g. {ImageName} or {User}.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# MITRE ATT&CK enterprise tactics in kill-chain order
TACTICS = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

SHELLS = r"\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\.exe$"
OFFICE = r"\\(winword|excel|powerpnt|outlook|onenote)\.exe$"
SCRIPTERS = r"\\(powershell|pwsh|rundll32|mshta|regsvr32|wscript|cscript)\.exe$"
USER_DIRS = r"\\(temp|appdata|users\\public|downloads|programdata)\\"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    tactic: str
    technique: str
    technique_name: str
    severity: str
    event_ids: tuple[int, ...]
    match: tuple[tuple[str, str], ...]
    story: str
    _compiled: tuple = field(default=(), compare=False, repr=False)

    def __post_init__(self) -> None:
        compiled = tuple((f, re.compile(p, re.I)) for f, p in self.match)
        object.__setattr__(self, "_compiled", compiled)

    @property
    def technique_url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.technique.replace(".", "/") + "/"

    def matches(self, event) -> bool:
        if event.event_id not in self.event_ids:
            return False
        return all(rx.search(event.get(f)) for f, rx in self._compiled)


@dataclass(frozen=True)
class ThresholdRule:
    """Fires when `count` matching events from the same key occur within `window` seconds."""
    id: str
    title: str
    tactic: str
    technique: str
    technique_name: str
    severity: str
    event_ids: tuple[int, ...]
    group_by: str
    count: int
    window: int
    story: str

    @property
    def technique_url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.technique.replace(".", "/") + "/"


RULES: list[Rule] = [
    Rule("LS-001", "Office application spawned a shell", "Initial Access", "T1566.001",
         "Spearphishing Attachment", "high", (1,),
         (("ParentImage", OFFICE), ("Image", SHELLS)),
         "{ParentImageName} opened by {User} spawned {ImageName}. A malicious document likely ran a macro."),
    Rule("LS-002", "Encoded PowerShell command", "Execution", "T1059.001",
         "PowerShell", "high", (1,),
         (("Image", r"\\(powershell|pwsh)\.exe$"),
          ("CommandLine", r"\s-(e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{16,}")),
         "PowerShell ran a Base64-encoded command, a common way to hide what a script does."),
    Rule("LS-003", "Download cradle", "Command and Control", "T1105",
         "Ingress Tool Transfer", "high", (1,),
         (("CommandLine", r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|"
                          r"start-bitstransfer|certutil.*-urlcache|bitsadmin.*/transfer)"),),
         "{ImageName} pulled a payload from the internet: `{CommandLine}`"),
    Rule("LS-004", "User discovery (whoami)", "Discovery", "T1033",
         "System Owner/User Discovery", "low", (1,),
         (("Image", r"\\whoami\.exe$"),),
         "The attacker checked who they are running as (`{CommandLine}`)."),
    Rule("LS-005", "Account / group enumeration", "Discovery", "T1087",
         "Account Discovery", "medium", (1,),
         (("Image", r"\\net1?\.exe$"), ("CommandLine", r"\s(user|group|localgroup|accounts)\b")),
         "Accounts were enumerated: `{CommandLine}`"),
    Rule("LS-006", "System information discovery", "Discovery", "T1082",
         "System Information Discovery", "low", (1,),
         (("Image", r"\\(systeminfo|hostname)\.exe$"),),
         "The host was fingerprinted with {ImageName}."),
    Rule("LS-007", "Domain trust discovery", "Discovery", "T1482",
         "Domain Trust Discovery", "medium", (1,),
         (("Image", r"\\nltest\.exe$"), ("CommandLine", r"(domain_trusts|dclist|/dsgetdc)")),
         "Domain trusts and controllers were mapped: `{CommandLine}`"),
    Rule("LS-008", "LSASS memory access", "Credential Access", "T1003.001",
         "LSASS Memory", "critical", (10,),
         (("TargetImage", r"\\lsass\.exe$"),
          ("GrantedAccess", r"^0x(1010|1410|1438|143a|1fffff|1f3fff)$")),
         "{SourceImageName} opened lsass.exe with {GrantedAccess} access, which is how credential dumpers like Mimikatz work."),
    Rule("LS-009", "Registry Run key persistence", "Persistence", "T1547.001",
         "Registry Run Keys / Startup Folder", "high", (13,),
         (("TargetObject", r"\\currentversion\\run(once)?\\"),),
         "{ImageName} added an autostart entry `{TargetObject}` -> `{Details}`."),
    Rule("LS-010", "Scheduled task created", "Persistence", "T1053.005",
         "Scheduled Task", "medium", (1,),
         (("Image", r"\\schtasks\.exe$"), ("CommandLine", r"/create")),
         "A scheduled task was created for persistence: `{CommandLine}`"),
    Rule("LS-011", "Remote execution with PsExec", "Lateral Movement", "T1569.002",
         "Service Execution", "high", (1,),
         (("Image", r"\\psexec(64)?\.exe$"),),
         "The attacker moved laterally with PsExec: `{CommandLine}`"),
    Rule("LS-012", "Security event log cleared", "Defense Evasion", "T1070.001",
         "Clear Windows Event Logs", "critical", (1102,),
         (),
         "The Security event log was cleared by {SubjectUserName}. Someone is covering their tracks."),
    Rule("LS-013", "Event log cleared via wevtutil", "Defense Evasion", "T1070.001",
         "Clear Windows Event Logs", "critical", (1,),
         (("Image", r"\\wevtutil\.exe$"), ("CommandLine", r"\s(cl|clear-log)\s")),
         "Event logs were wiped: `{CommandLine}`"),
    Rule("LS-014", "Shadow copies deleted", "Impact", "T1490",
         "Inhibit System Recovery", "critical", (1,),
         (("CommandLine", r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|wbadmin.*delete)"),),
         "Shadow copies were deleted (`{CommandLine}`), a classic step right before ransomware encrypts."),
    Rule("LS-015", "Script engine made a network connection", "Command and Control", "T1071.001",
         "Web Protocols", "medium", (3,),
         (("Image", SCRIPTERS),),
         "{ImageName} connected out to {DestinationIp}:{DestinationPort}, possible C2 beaconing."),
    Rule("LS-016", "Executable dropped in user-writable folder", "Execution", "T1204.002",
         "Malicious File", "medium", (11,),
         (("TargetFilename", USER_DIRS + r".*\.(exe|dll|ps1|bat|vbs|hta|scr)$"),),
         "{ImageName} dropped `{TargetFilename}`."),
    Rule("LS-017", "Rundll32 running from user folder", "Defense Evasion", "T1218.011",
         "Rundll32", "high", (1,),
         (("Image", r"\\rundll32\.exe$"), ("CommandLine", USER_DIRS)),
         "rundll32.exe loaded a DLL from a user-writable path: `{CommandLine}`"),
]

THRESHOLD_RULES: list[ThresholdRule] = [
    ThresholdRule("LS-100", "Brute-force logon attempts", "Credential Access", "T1110",
                  "Brute Force", "high", (4625,), "IpAddress", count=5, window=120,
                  story="{count} failed logons from {key} within {window}s, which looks like password guessing."),
]
