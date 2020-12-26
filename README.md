# suricata-smb-print
Dump Suricata SMB-related payload in "user-friendlier" format

Dumping SMB payload in printable format (`payload-printable`) can be extremely handy for detecting lateral movement and exact binaries/scripts that were transferred or used by the attacker.
Unfortunately, printable SMB payload is not easily readable because of the lossy format and binary nature of the protocol itself.

This script *beautifies* the output and creates more condensed output more suitable for both manual and automatic triage.

Raw logs:
![Raw](https://i.imgur.com/a/BoyfWdQ.png)

Beautified logs:
![Beautified](https://i.imgur.com/a/xoYOZma.png)
