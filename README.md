# suricata-smb-print
[![License](https://img.shields.io/badge/license-MIT-green.svg)](https://github.com/aelth/suricata-smb-print/blob/main/LICENSE)

Dumping SMB payload in printable format (`payload-printable`) can be extremely handy for detecting lateral movement and exact binaries/scripts that were transferred or used by the attacker.
Unfortunately, printable SMB payload is not easily readable because of the lossy format and binary nature of the protocol itself.

This script *beautifies* the output and creates more condensed output more suitable for both manual and automatic triage.

Raw logs:
![Raw](https://i.imgur.com/L3Z1sm8.png)

Beautified logs:
![Beautified](https://i.imgur.com/BhDvuqJ.png)
