"""
Embedded MITRE ATT&CK keyword-to-tactic/technique mappings for ATT&CKLens MVP.

This module provides a lightweight, zero-dependency heuristic mapping from
security observation keywords to MITRE ATT&CK tactics and techniques.
No external API calls or data fetching required.
"""

from typing import Dict, List, Tuple, Optional

# Keyword-to-tactic mapping with associated techniques
# Each entry: keyword -> (tactic, technique_id, technique_name, confidence_boost)
# Confidence boost: "high" indicators get +1, "medium" get 0, "low" get -1
ATTACK_MAPPINGS: Dict[str, Tuple[str, str, str, str]] = {
    # Initial Access
    "ssh login": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "high"),
    "ssh bruteforce": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "high"),
    "failed ssh": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "medium"),
    "rdp login": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "high"),
    "rdp bruteforce": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "high"),
    "failed rdp": ("Initial Access", "T1110.001", "Brute Force: Password Guessing", "medium"),
    "vpn login": ("Initial Access", "T1110", "Brute Force", "medium"),
    "vpn bruteforce": ("Initial Access", "T1110", "Brute Force", "high"),
    "phishing": ("Initial Access", "T1566", "Phishing", "high"),
    "spearphishing": ("Initial Access", "T1566.001", "Phishing: Spearphishing Attachment", "high"),
    "malicious email": ("Initial Access", "T1566", "Phishing", "medium"),
    "drive-by": ("Initial Access", "T1189", "Drive-by Compromise", "high"),
    "exploit public": ("Initial Access", "T1190", "Exploit Public-Facing Application", "high"),
    "valid accounts": ("Initial Access", "T1078", "Valid Accounts", "medium"),
    "default credentials": ("Initial Access", "T1078", "Valid Accounts", "high"),
    "credential stuffing": ("Initial Access", "T1110.004", "Brute Force: Credential Stuffing", "high"),
    "password spray": ("Initial Access", "T1110.003", "Brute Force: Password Spraying", "high"),

    # Execution
    "powershell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell", "high"),
    "cmd.exe": ("Execution", "T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "medium"),
    "bash": ("Execution", "T1059.004", "Command and Scripting Interpreter: Unix Shell", "medium"),
    "wscript": ("Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", "medium"),
    "cscript": ("Execution", "T1059.005", "Command and Scripting Interpreter: Visual Basic", "medium"),
    "mshta": ("Execution", "T1218.005", "Signed Binary Proxy Execution: Mshta", "high"),
    "rundll32": ("Execution", "T1218.011", "Signed Binary Proxy Execution: Rundll32", "high"),
    "regsvr32": ("Execution", "T1218.010", "Signed Binary Proxy Execution: Regsvr32", "high"),
    "certutil": ("Execution", "T1105", "Ingress Tool Transfer", "high"),
    "bitsadmin": ("Execution", "T1197", "BITS Jobs", "medium"),
    "wmic": ("Execution", "T1047", "Windows Management Instrumentation", "medium"),
    "scheduled task": ("Execution", "T1053.005", "Scheduled Task/Job: Scheduled Task", "high"),
    "cron": ("Execution", "T1053.003", "Scheduled Task/Job: Cron", "high"),
    "service creation": ("Execution", "T1543.003", "Create or Modify System Process: Windows Service", "high"),
    "script": ("Execution", "T1059", "Command and Scripting Interpreter", "low"),

    # Persistence
    "registry run": ("Persistence", "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "high"),
    "startup folder": ("Persistence", "T1547.001", "Boot or Logon Autostart Execution: Startup Folder", "high"),
    "service install": ("Persistence", "T1543.003", "Create or Modify System Process: Windows Service", "high"),
    "scheduled task persistence": ("Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task", "high"),
    "cron persistence": ("Persistence", "T1053.003", "Scheduled Task/Job: Cron", "high"),
    "wmi subscription": ("Persistence", "T1546.003", "Event Triggered Execution: WMI Event Subscription", "high"),
    "dll hijack": ("Persistence", "T1574.001", "Hijack Execution Flow: DLL Search Order Hijacking", "high"),
    "ssh key": ("Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys", "high"),
    "authorized_keys": ("Persistence", "T1098.004", "Account Manipulation: SSH Authorized Keys", "high"),
    "add user": ("Persistence", "T1136.001", "Create Account: Local Account", "medium"),
    "create account": ("Persistence", "T1136", "Create Account", "medium"),
    "golden ticket": ("Persistence", "T1558.001", "Steal or Forge Kerberos Tickets: Golden Ticket", "high"),
    "silver ticket": ("Persistence", "T1558.002", "Steal or Forge Kerberos Tickets: Silver Ticket", "high"),

    # Privilege Escalation
    "uac bypass": ("Privilege Escalation", "T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", "high"),
    "token impersonation": ("Privilege Escalation", "T1134.001", "Access Token Manipulation: Token Impersonation/Theft", "high"),
    "dll injection": ("Privilege Escalation", "T1055.001", "Process Injection: Dynamic-link Library Injection", "high"),
    "process injection": ("Privilege Escalation", "T1055", "Process Injection", "high"),
    "exploit kernel": ("Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", "high"),
    "sudo": ("Privilege Escalation", "T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "medium"),
    "setuid": ("Privilege Escalation", "T1548.001", "Abuse Elevation Control Mechanism: Setuid and Setgid", "medium"),
    "bypass uac": ("Privilege Escalation", "T1548.002", "Abuse Elevation Control Mechanism: Bypass User Account Control", "high"),

    # Defense Evasion
    "disable defender": ("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools", "high"),
    "disable antivirus": ("Defense Evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools", "high"),
    "delete logs": ("Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "high"),
    "clear event log": ("Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "high"),
    "wevtutil": ("Defense Evasion", "T1070.001", "Indicator Removal: Clear Windows Event Logs", "high"),
    "timestomp": ("Defense Evasion", "T1070.006", "Indicator Removal: Timestomp", "high"),
    "masquerade": ("Defense Evasion", "T1036", "Masquerading", "medium"),
    "rename binary": ("Defense Evasion", "T1036.003", "Masquerading: Rename System Utilities", "medium"),
    "hide file": ("Defense Evasion", "T1564.001", "Hide Artifacts: Hidden Files and Directories", "medium"),
    "hidden file": ("Defense Evasion", "T1564.001", "Hide Artifacts: Hidden Files and Directories", "medium"),
    "obfuscate": ("Defense Evasion", "T1027", "Obfuscated/Stored Information", "medium"),
    "encoded command": ("Defense Evasion", "T1027.010", "Obfuscated/Stored Information: Command Obfuscation", "high"),
    "base64": ("Defense Evasion", "T1027.010", "Obfuscated/Stored Information: Command Obfuscation", "medium"),
    "lolbas": ("Defense Evasion", "T1218", "Signed Binary Proxy Execution", "medium"),
    "lolbin": ("Defense Evasion", "T1218", "Signed Binary Proxy Execution", "medium"),

    # Credential Access
    "dump credentials": ("Credential Access", "T1003", "OS Credential Dumping", "high"),
    "lsass": ("Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "high"),
    "sam dump": ("Credential Access", "T1003.002", "OS Credential Dumping: Security Account Manager", "high"),
    "ntds.dit": ("Credential Access", "T1003.003", "OS Credential Dumping: NTDS", "high"),
    "mimikatz": ("Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "high"),
    "sekurlsa": ("Credential Access", "T1003.001", "OS Credential Dumping: LSASS Memory", "high"),
    "keylogger": ("Credential Access", "T1056.001", "Input Capture: Keylogging", "high"),
    "credential manager": ("Credential Access", "T1555.003", "Credentials from Password Stores: Credential Manager", "high"),
    "browser credentials": ("Credential Access", "T1555.003", "Credentials from Password Stores: Credential Manager", "medium"),
    "hash dump": ("Credential Access", "T1003", "OS Credential Dumping", "high"),
    "pass the hash": ("Credential Access", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "high"),
    "pass the ticket": ("Credential Access", "T1550.003", "Use Alternate Authentication Material: Pass the Ticket", "high"),
    "kerberoast": ("Credential Access", "T1558.003", "Steal or Forge Kerberos Tickets: Kerberoasting", "high"),
    "asreproast": ("Credential Access", "T1558.004", "Steal or Forge Kerberos Tickets: AS-REP Roasting", "high"),
    "brute force": ("Credential Access", "T1110", "Brute Force", "medium"),
    "password spray": ("Credential Access", "T1110.003", "Brute Force: Password Spraying", "high"),

    # Discovery
    "network scan": ("Discovery", "T1046", "Network Service Discovery", "medium"),
    "port scan": ("Discovery", "T1046", "Network Service Discovery", "medium"),
    "nmap": ("Discovery", "T1046", "Network Service Discovery", "medium"),
    "masscan": ("Discovery", "T1046", "Network Service Discovery", "medium"),
    "zmap": ("Discovery", "T1046", "Network Service Discovery", "medium"),
    "enum": ("Discovery", "T1087", "Account Discovery", "medium"),
    "enumerate": ("Discovery", "T1087", "Account Discovery", "medium"),
    "ad enum": ("Discovery", "T1087.002", "Account Discovery: Domain Account", "medium"),
    "bloodhound": ("Discovery", "T1087.002", "Account Discovery: Domain Account", "high"),
    "sharphound": ("Discovery", "T1087.002", "Account Discovery: Domain Account", "high"),
    "ldap query": ("Discovery", "T1087.002", "Account Discovery: Domain Account", "medium"),
    "dns query": ("Discovery", "T1018", "Remote System Discovery", "medium"),
    "system info": ("Discovery", "T1082", "System Information Discovery", "low"),
    "process list": ("Discovery", "T1057", "Process Discovery", "low"),
    "netstat": ("Discovery", "T1049", "System Network Connections Discovery", "low"),
    "arp": ("Discovery", "T1016", "System Network Configuration Discovery", "low"),
    "whoami": ("Discovery", "T1033", "System Owner/User Discovery", "low"),

    # Lateral Movement
    "psexec": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares", "high"),
    "smb": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares", "medium"),
    "wmiexec": ("Lateral Movement", "T1021.003", "Remote Services: Distributed Component Object Model", "high"),
    "winrm": ("Lateral Movement", "T1021.006", "Remote Services: Windows Remote Management", "high"),
    "ssh lateral": ("Lateral Movement", "T1021.004", "Remote Services: SSH", "medium"),
    "ssh connection": ("Lateral Movement", "T1021.004", "Remote Services: SSH", "medium"),
    "rdp": ("Lateral Movement", "T1021.001", "Remote Services: Remote Desktop Protocol", "medium"),
    "pass the hash lateral": ("Lateral Movement", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "high"),
    "pth": ("Lateral Movement", "T1550.002", "Use Alternate Authentication Material: Pass the Hash", "high"),
    "remote execution": ("Lateral Movement", "T1021", "Remote Services", "low"),

    # Collection
    "data staging": ("Collection", "T1074", "Data Staged", "high"),
    "archive data": ("Collection", "T1560", "Archive Collected Data", "medium"),
    "clipboard": ("Collection", "T1115", "Clipboard Data", "medium"),
    "screen capture": ("Collection", "T1113", "Screen Capture", "medium"),
    "keylogger collection": ("Collection", "T1056.001", "Input Capture: Keylogging", "high"),
    "email collection": ("Collection", "T1114", "Email Collection", "medium"),

    # Command and Control
    "c2": ("Command and Control", "T1071", "Application Layer Protocol", "high"),
    "command and control": ("Command and Control", "T1071", "Application Layer Protocol", "high"),
    "beacon": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "dns tunnel": ("Command and Control", "T1071.004", "Application Layer Protocol: DNS", "high"),
    "dns exfil": ("Command and Control", "T1048.003", "Exfiltration Over Alternative Protocol: DNS", "high"),
    "dns request": ("Command and Control", "T1071.004", "Application Layer Protocol: DNS", "high"),
    "dns requests": ("Command and Control", "T1071.004", "Application Layer Protocol: DNS", "high"),
    "suspicious domain": ("Command and Control", "T1071.004", "Application Layer Protocol: DNS", "high"),
    "http beacon": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "https beacon": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "cobalt strike": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "sliver": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "metasploit": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", "high"),
    "custom protocol": ("Command and Control", "T1094", "Custom Command and Control Protocol", "high"),
    "domain fronting": ("Command and Control", "T1090.001", "Proxy: Internal Proxy", "high"),
    "proxy": ("Command and Control", "T1090", "Proxy", "medium"),
    "tls": ("Command and Control", "T1573.001", "Encrypted Channel: Symmetric Cryptography", "medium"),
    "encrypted channel": ("Command and Control", "T1573", "Encrypted Channel", "medium"),

    # Exfiltration
    "exfil": ("Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", "high"),
    "data exfil": ("Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", "high"),
    "exfiltrate": ("Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", "high"),
    "upload": ("Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", "medium"),
    "download": ("Exfiltration", "T1041", "Exfiltration Over Command and Control Channel", "medium"),
    "cloud storage": ("Exfiltration", "T1567.002", "Exfiltration Over Web Service: Exfiltration to Cloud Storage", "high"),
    "web upload": ("Exfiltration", "T1567", "Exfiltration Over Web Service", "medium"),
    "dns exfiltration": ("Exfiltration", "T1048.003", "Exfiltration Over Alternative Protocol: DNS", "high"),

    # Impact
    "ransomware": ("Impact", "T1486", "Data Encrypted for Impact", "high"),
    "encrypt": ("Impact", "T1486", "Data Encrypted for Impact", "medium"),
    "wiper": ("Impact", "T1489", "Service Stop", "high"),
    "destroy data": ("Impact", "T1485", "Data Destruction", "high"),
    "delete backup": ("Impact", "T1490", "Inhibit System Recovery", "high"),
    "disable recovery": ("Impact", "T1490", "Inhibit System Recovery", "high"),
    "defacement": ("Impact", "T1491.001", "Defacement: Internal Defacement", "high"),
    "shutdown": ("Impact", "T1529", "System Shutdown/Reboot", "medium"),
    "reboot": ("Impact", "T1529", "System Shutdown/Reboot", "medium"),
}


# Tactic order for consistent output
TACTIC_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def get_attack_mapping(keyword: str) -> Optional[Tuple[str, str, str, str]]:
    """
    Look up a keyword in the ATT&CK mappings.

    Returns: (tactic, technique_id, technique_name, confidence_level) or None
    """
    keyword_lower = keyword.lower().strip()
    # Try exact match first
    if keyword_lower in ATTACK_MAPPINGS:
        return ATTACK_MAPPINGS[keyword_lower]
    # Try partial matches (keyword in mapping key or mapping key in keyword)
    for map_key, value in ATTACK_MAPPINGS.items():
        if map_key in keyword_lower or keyword_lower in map_key:
            return value
    return None


def find_all_mappings(text: str) -> List[Tuple[str, str, str, str, str]]:
    """
    Find all ATT&CK mappings that match keywords in the input text.

    Returns list of (matched_keyword, tactic, technique_id, technique_name, confidence)
    """
    text_lower = text.lower()
    matches = []
    for keyword, (tactic, tech_id, tech_name, confidence) in ATTACK_MAPPINGS.items():
        if keyword in text_lower:
            matches.append((keyword, tactic, tech_id, tech_name, confidence))
    return matches


def rank_mappings(matches: List[Tuple[str, str, str, str, str]]) -> List[Tuple[str, str, str, str, str]]:
    """
    Rank matches by confidence and tactic priority.
    Higher confidence first, then earlier tactic in ATT&CK matrix.
    """
    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    tactic_rank = {tactic: i for i, tactic in enumerate(TACTIC_ORDER)}

    def sort_key(match):
        _, tactic, _, _, confidence = match
        return (-confidence_rank.get(confidence, 0), tactic_rank.get(tactic, 999))

    return sorted(matches, key=sort_key)