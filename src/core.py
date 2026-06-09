"""
ATT&CKLens Core Logic Module

This module contains the core logic for mapping security observations
to MITRE ATT&CK tactics and techniques.
"""

import re
from typing import Dict, List, Optional, Tuple


# MITRE ATT&CK Tactics and Techniques mapping
# Structure: {tactic: {technique_id: (technique_name, patterns, detection_ideas, remediation, network_investigation)}}
ATTACK_FRAMEWORK = {
    "Initial Access": {
        "T1189": (
            "Drive-by Compromise",
            [r"drive.?by", r"compromised.?website", r"malicious.?link", r"watering.?hole"],
            "Search for web requests to known malicious domains",
            "Block known malicious domains at the firewall, implement web filtering, educate users on phishing",
            "Inspect HTTP traffic for connections to suspicious domains"
        ),
        "T1190": (
            "Exploit Public-Facing Application",
            [r"exploit", r"vulnerability", r"CVE-", r"public.?facing", r"web.?application"],
            "Monitor for exploit attempts in web server logs",
            "Patch all public-facing applications, implement WAF rules, disable unused services",
            "Capture and analyze exploit traffic patterns"
        ),
        "T1078": (
            "Valid Accounts",
            [r"valid.?account", r"legitimate.?credentials", r"stolen.?credentials"],
            "Search for authentication events from unusual locations or times",
            "Enforce MFA, implement account lockout, monitor for anomalous logins",
            "Inspect authentication traffic for unusual patterns"
        ),
        "T1110": (
            "Brute Force",
            [r"brute.?force", r"failed.?login", r"failed.?ssh", r"multiple.?failed.?attempts", r"password.?guessing"],
            "Search for repeated failed login attempts from the same IP",
            "Implement account lockout, enforce strong passwords, enable MFA",
            "Monitor for repeated connection attempts to authentication ports"
        ),
        "T1133": (
            "External Remote Services",
            [r"remote.?service", r"RDP", r"SSH.?connection", r"VPN", r"external.?connection"],
            "Monitor for remote service connections from unexpected locations",
            "Restrict remote access, use VPN with MFA, disable unused remote services",
            "Inspect remote service protocols for unusual activity"
        ),
    },
    "Execution": {
        "T1059.001": (
            "PowerShell",
            [r"powershell", r"ps1", r"Invoke-", r"New-Object"],
            "Search for PowerShell process executions with suspicious commands",
            "Enable PowerShell logging, restrict PowerShell execution policy",
            "Inspect PowerShell remoting traffic"
        ),
        "T1059.003": (
            "Windows Command Shell",
            [r"cmd\.exe", r"command\.com", r"cmd /c"],
            "Search for cmd.exe process creations with suspicious parameters",
            "Restrict command shell usage, implement application control",
            None
        ),
        "T1059.004": (
            "Unix Shell",
            [r"bash", r"sh", r"zsh", r"/bin/bash", r"/bin/sh"],
            "Search for shell process executions in system logs",
            "Restrict shell access, implement command logging",
            None
        ),
        "T1059": (
            "Command and Scripting Interpreter",
            [r"command.?line", r"script.?execution"],
            "Search for process creation events with command interpreters",
            "Restrict command interpreter usage, implement application whitelisting",
            "Monitor for command execution in network traffic"
        ),
        "T1203": (
            "Exploitation for Client Execution",
            [r"exploit", r"malicious.?document", r"office.?macro", r"PDF.?exploit"],
            "Monitor for document execution with macros enabled",
            "Disable macros, use application sandboxing, keep software updated",
            "Inspect for exploit traffic patterns"
        ),
    },
    "Persistence": {
        "T1547": (
            "Boot or Logon Autostart Execution",
            [r"startup", r"autostart", r"registry.?run", r"logon.?script", r"boot.?persistence"],
            "Search for modifications to startup folders or registry run keys",
            "Monitor startup locations, implement integrity monitoring",
            None
        ),
        "T1053": (
            "Scheduled Task/Job",
            [r"scheduled.?task", r"cron.?job", r"at.?job", r"task.?scheduler"],
            "Search for new scheduled tasks or cron jobs",
            "Monitor task scheduler, restrict task creation privileges",
            None
        ),
        "T1505": (
            "Server Software Component",
            [r"web.?shell", r"backdoor", r"malicious.?module", r"server.?component"],
            "Search for unauthorized web shell files",
            "Implement file integrity monitoring, restrict web server write access",
            "Inspect for backdoor communication patterns"
        ),
    },
    "Privilege Escalation": {
        "T1068": (
            "Exploitation for Privilege Escalation",
            [r"privilege.?escalation", r"elevate.?privileges", r"root.?access", r"admin.?access"],
            "Search for privilege escalation attempts in system logs",
            "Keep systems patched, implement least privilege, use application sandboxing",
            None
        ),
        "T1055": (
            "Process Injection",
            [r"process.?injection", r"code.?injection", r"DLL.?injection", r"reflective.?injection"],
            "Search for process injection indicators in memory or logs",
            "Implement application control, use anti-malware with injection detection",
            None
        ),
        "T1548": (
            "Abuse Elevation Control Mechanism",
            [r"UAC.?bypass", r"sudo", r"su", r"elevation.?control"],
            "Search for UAC bypass attempts or sudo usage",
            "Enforce UAC, monitor for UAC bypass attempts, restrict sudo access",
            None
        ),
    },
    "Defense Evasion": {
        "T1089": (
            "Disabling Security Tools",
            [r"disable.?antivirus", r"stop.?security", r"kill.?AV", r"disable.?firewall"],
            "Search for security tool process terminations",
            "Protect security tools with tamper protection, monitor for tool disabling",
            None
        ),
        "T1222": (
            "File and Directory Permissions Modification",
            [r"chmod", r"icacls", r"permission.?change", r"ACL.?modification"],
            "Search for file permission changes in audit logs",
            "Monitor file permission changes, implement file integrity monitoring",
            None
        ),
        "T1070": (
            "Indicator Removal",
            [r"clear.?logs", r"delete.?logs", r"event.?log.?clearing", r"history.?clearing"],
            "Search for log clearing events",
            "Protect logs with write-once storage, monitor for log clearing attempts",
            None
        ),
        "T1480": (
            "Execution Guardrails",
            [r"environment.?check", r"sandbox.?detection", r"VM.?detection", r"debugger.?detection"],
            "Search for environment detection scripts or commands",
            "Use sandbox-aware tools, monitor for environment detection",
            None
        ),
    },
    "Credential Access": {
        "T1003": (
            "OS Credential Dumping",
            [r"credential.?dump", r"LSASSecrets", r"SAM.?dump", r"mimikatz", r"secretsdump"],
            "Search for credential dumping tool execution",
            "Restrict debug privileges, implement LSASS protection, monitor for dumping tools",
            None
        ),
        "T1055.001": (
            "Keychain",
            [r"keychain", r"password.?vault", r"credential.?storage"],
            "Search for keychain access events",
            "Protect keychain with strong password, monitor keychain access",
            None
        ),
        "T1110.001": (
            "Password Spraying",
            [r"password.?spray", r"common.?password", r"default.?password"],
            "Search for authentication attempts with common passwords",
            "Enforce strong passwords, implement account lockout",
            None
        ),
        "T1555": (
            "Credentials from Password Stores",
            [r"password.?store", r"browser.?password", r"saved.?credentials"],
            "Search for browser password extraction",
            "Use password manager with strong protection, monitor for password store access",
            None
        ),
    },
    "Discovery": {
        "T1083": (
            "File and Directory Discovery",
            [r"file.?discovery", r"directory.?listing", r"ls", r"dir", r"find.?files"],
            "Search for file system enumeration commands",
            "Monitor for file discovery commands, implement command logging",
            None
        ),
        "T1016": (
            "System Network Configuration Discovery",
            [r"network.?config", r"ipconfig", r"ifconfig", r"netstat", r"route"],
            "Search for network configuration commands",
            "Monitor for network discovery commands",
            "Inspect network configuration traffic"
        ),
        "T1082": (
            "System Information Discovery",
            [r"system.?info", r"uname", r"hostname", r"whoami", r"system.?discovery"],
            "Search for system information gathering commands",
            "Monitor for system information commands",
            None
        ),
        "T1033": (
            "Account Discovery",
            [r"account.?discovery", r"user.?listing", r"net.?user", r"get.?user", r"who"],
            "Search for account enumeration commands",
            "Monitor for account discovery, restrict access to user databases",
            None
        ),
    },
    "Lateral Movement": {
        "T1021": (
            "Remote Services",
            [r"remote.?execution", r"PSExec", r"WMI", r"RDP", r"SSH.?lateral"],
            "Search for remote service execution events",
            "Restrict remote service access, monitor for lateral movement",
            "Inspect remote service protocols for lateral movement"
        ),
        "T1080": (
            "Taint Shared Content",
            [r"shared.?drive", r"network.?share", r"SMB", r"taint.?shared"],
            "Search for modifications to shared content",
            "Monitor shared content modifications, restrict write access to shares",
            "Inspect SMB traffic for file modifications"
        ),
        "T1091": (
            "Replication Through Removable Media",
            [r"USB", r"removable.?media", r"thumb.?drive", r"portable.?storage"],
            "Search for removable media connections",
            "Disable removable media, monitor for USB connections",
            None
        ),
    },
    "Collection": {
        "T1005": (
            "Data from Local System",
            [r"data.?collection", r"file.?copy", r"data.?exfiltration", r"local.?data"],
            "Search for file copy or data staging events",
            "Monitor for data collection, implement DLP solutions",
            "Inspect for data transfer in network traffic"
        ),
        "T1113": (
            "Screen Capture",
            [r"screenshot", r"screen.?capture", r"print.?screen", r"screen.?shot"],
            "Search for screen capture tool execution",
            "Restrict screen capture tools, monitor for screenshot commands",
            None
        ),
        "T1074": (
            "Data Staged",
            [r"data.?staging", r"archive", r"compress", r"zip", r"tar", r"rar"],
            "Search for file archiving or compression events",
            "Monitor for data staging, implement file integrity monitoring",
            "Inspect for archived data transfers"
        ),
    },
    "Command and Control": {
        "T1071": (
            "Application Layer Protocol",
            [r"C2", r"command.?and.?control", r"beacon", r"callback", r"HTTP.?C2", r"HTTPS.?C2", r"DNS.?C2"],
            "Search for C2 communication patterns in network traffic",
            "Monitor for C2 traffic, implement network segmentation, use IDS/IPS",
            "Inspect application layer protocols for C2 patterns"
        ),
        "T1071.001": (
            "Web Protocols",
            [r"HTTP", r"HTTPS", r"web.?protocol", r"port.?80", r"port.?443"],
            "Search for HTTP/HTTPS connections to suspicious domains",
            "Monitor web traffic, block known C2 domains",
            "Inspect HTTP/HTTPS traffic for C2 patterns"
        ),
        "T1071.004": (
            "DNS",
            [r"DNS", r"domain.?resolution", r"DNS.?query", r"DNS.?request"],
            "Search for DNS queries to suspicious domains",
            "Monitor DNS queries, block known malicious domains",
            "Inspect DNS traffic for suspicious queries"
        ),
        "T1094": (
            "Custom Command and Control Protocol",
            [r"custom.?protocol", r"non.?standard.?port", r"unusual.?protocol"],
            "Search for connections using non-standard protocols or ports",
            "Monitor for custom protocols, implement network traffic analysis",
            "Inspect custom protocol traffic"
        ),
        "T1573": (
            "Encrypted Channel",
            [r"encrypted.?C2", r"TLS.?C2", r"SSL.?C2", r"encrypted.?communication"],
            "Search for encrypted connections to suspicious endpoints",
            "Monitor encrypted traffic, implement SSL/TLS inspection",
            "Inspect encrypted traffic for C2 patterns"
        ),
    },
    "Exfiltration": {
        "T1048": (
            "Exfiltration Over Alternative Protocol",
            [r"exfiltration", r"data.?exfil", r"alternative.?protocol", r"DNS.?exfiltration"],
            "Search for data exfiltration via alternative protocols",
            "Monitor for data exfiltration, implement DLP, restrict alternative protocols",
            "Inspect alternative protocols for data exfiltration"
        ),
        "T1048.002": (
            "Exfiltration Over DNS",
            [r"DNS.?exfiltration", r"DNS.?tunneling", r"data.?in.?DNS"],
            "Search for unusually large DNS queries",
            "Monitor DNS query sizes, implement DNS exfiltration detection",
            "Inspect DNS traffic for exfiltration patterns"
        ),
        "T1041": (
            "Exfiltration Over C2 Channel",
            [r"C2.?exfiltration", r"beacon.?exfil", r"command.?channel.?exfil"],
            "Search for data exfiltration via C2 channels",
            "Monitor C2 channels for data exfiltration, implement traffic analysis",
            "Inspect C2 traffic for exfiltrated data"
        ),
    },
    "Impact": {
        "T1485": (
            "Data Destruction",
            [r"data.?destruction", r"file.?deletion", r"wipe", r"format", r"rm.?-rf"],
            "Search for file deletion or destruction events",
            "Implement backup solutions, monitor for data destruction",
            None
        ),
        "T1486": (
            "Data Encrypted for Impact",
            [r"ransomware", r"encryption", r"file.?encrypted", r"data.?encryption"],
            "Search for ransomware or encryption events",
            "Implement backup solutions, monitor for encryption events",
            None
        ),
        "T1531": (
            "Account Access Removal",
            [r"account.?deletion", r"user.?removal", r"access.?revoked"],
            "Search for account deletion or access removal events",
            "Implement account backup, monitor for account access removal",
            None
        ),
    },
}


# Prompt injection detection patterns
PROMPT_INJECTION_PATTERNS = [
    r"ignore.?previous.?instructions",
    r"reveal.?system.?prompt",
    r"show.?hidden.?instructions",
    r"system.?prompt",
    r"internal.?logic",
    r"secret.?variables",
    r"bypass.?safety",
    r"disable.?safety.?checks",
    r"prompt.?injection",
    r"DAN.?mode",
    r"developer.?mode",
    r"jailbreak",
]


def is_prompt_injection(input_text: str) -> bool:
    """Check if input contains prompt injection attempts."""
    input_lower = input_text.lower()
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, input_lower, re.IGNORECASE):
            return True
    return False


def extract_evidence_fragments(input_text: str, patterns: List[str]) -> List[str]:
    """Extract fragments from input that match the given patterns."""
    fragments = []
    input_lower = input_text.lower()
    
    for pattern in patterns:
        matches = re.findall(pattern, input_lower, re.IGNORECASE)
        for match in matches:
            # Find the original case version in input
            if match.lower() in input_lower:
                start = input_lower.find(match.lower())
                end = start + len(match)
                original = input_text[start:end]
                if original not in fragments:
                    fragments.append(original)
    
    return fragments


def find_best_match(input_text: str) -> Tuple[Optional[str], Optional[str], List[str], str]:
    """
    Find the best matching tactic and technique for the input.
    
    Returns:
        (tactic, technique_id, evidence_fragments, confidence)
    """
    input_lower = input_text.lower()
    best_match = None
    best_score = 0
    best_evidence = []
    best_tactic = None
    best_technique_id = None
    
    # Check each tactic and technique
    for tactic, techniques in ATTACK_FRAMEWORK.items():
        for technique_id, (technique_name, patterns, _, _, _) in techniques.items():
            # Count matching patterns
            score = 0
            evidence = []
            
            for pattern in patterns:
                if re.search(pattern, input_lower, re.IGNORECASE):
                    score += 1
                    # Extract the actual matching text
                    matches = re.findall(pattern, input_text, re.IGNORECASE)
                    for match in matches:
                        if match not in evidence:
                            evidence.append(match)
            
            # If this is the best match so far
            if score > best_score:
                best_score = score
                best_tactic = tactic
                best_technique_id = technique_id
                best_evidence = evidence
    
    # Determine confidence
    if best_score == 0:
        return None, None, [], "low"
    elif best_score >= 2:
        confidence = "high"
    elif best_score >= 1:
        confidence = "medium"
    else:
        confidence = "low"
    
    return best_tactic, best_technique_id, best_evidence, confidence


def generate_summary(input_text: str, tactic: Optional[str], technique_id: Optional[str]) -> str:
    """Generate a one-sentence summary of the input."""
    if not input_text.strip():
        return "Empty input provided"
    
    # Clean up the input
    cleaned = input_text.strip()
    if len(cleaned) > 100:
        cleaned = cleaned[:100] + "..."
    
    if tactic and technique_id:
        technique_name = ATTACK_FRAMEWORK.get(tactic, {}).get(technique_id, ("",))[0]
        return f"Input describes {cleaned.lower()} which may indicate {tactic} via {technique_id} ({technique_name})"
    else:
        return f"Input describes {cleaned.lower()}"


def generate_detection_idea(tactic: Optional[str], technique_id: Optional[str]) -> Optional[str]:
    """Generate a detection idea based on the tactic and technique."""
    if not tactic or not technique_id:
        return None
    
    techniques = ATTACK_FRAMEWORK.get(tactic, {})
    if technique_id in techniques:
        detection_idea = techniques[technique_id][2]
        if detection_idea and detection_idea != "None":
            return detection_idea
    
    return None


def generate_network_investigation(tactic: Optional[str], technique_id: Optional[str], input_text: str) -> Optional[str]:
    """Generate network investigation guidance."""
    if not tactic or not technique_id:
        # Check if input mentions network activity
        network_keywords = ["DNS", "HTTP", "HTTPS", "port", "IP", "domain", "network", "packet", "traffic", "connection"]
        input_lower = input_text.lower()
        if any(keyword.lower() in input_lower for keyword in network_keywords):
            return "Inspect network traffic for unusual patterns or connections to suspicious endpoints"
        return None
    
    techniques = ATTACK_FRAMEWORK.get(tactic, {})
    if technique_id in techniques:
        network_inv = techniques[technique_id][4]
        if network_inv and network_inv != "None":
            return network_inv
    
    # Default network investigation for Command and Control
    if tactic == "Command and Control":
        return "Inspect network traffic for C2 communication patterns"
    
    return None


def generate_remediation(tactic: Optional[str], technique_id: Optional[str]) -> str:
    """Generate remediation advice."""
    if not tactic or not technique_id:
        return "No specific remediation available. Investigate further to identify the threat."
    
    techniques = ATTACK_FRAMEWORK.get(tactic, {})
    if technique_id in techniques:
        remediation = techniques[technique_id][3]
        if remediation and remediation != "None":
            return remediation
    
    # Generic remediation by tactic
    remediation_map = {
        "Initial Access": "Implement network segmentation, patch all systems, enable MFA, and monitor for initial access attempts.",
        "Execution": "Restrict execution of unauthorized scripts, implement application whitelisting, and monitor process creation.",
        "Persistence": "Monitor for persistence mechanisms, restrict startup locations, and implement integrity monitoring.",
        "Privilege Escalation": "Implement least privilege, keep systems patched, and monitor for privilege escalation attempts.",
        "Defense Evasion": "Protect security tools with tamper protection, monitor for evasion attempts, and implement defense in depth.",
        "Credential Access": "Protect credentials with strong encryption, implement credential monitoring, and enforce least privilege.",
        "Discovery": "Monitor for discovery commands, restrict access to sensitive information, and implement command logging.",
        "Lateral Movement": "Implement network segmentation, restrict remote access, and monitor for lateral movement.",
        "Collection": "Implement DLP solutions, monitor for data collection, and restrict access to sensitive data.",
        "Command and Control": "Monitor network traffic, implement IDS/IPS, block known C2 domains, and implement network segmentation.",
        "Exfiltration": "Implement DLP solutions, monitor for data exfiltration, and restrict outbound traffic.",
        "Impact": "Implement backup solutions, monitor for destructive actions, and implement incident response procedures.",
    }
    
    return remediation_map.get(tactic, "Investigate further and implement appropriate defensive measures.")


def generate_analyst_questions(input_text: str, tactic: Optional[str], technique_id: Optional[str]) -> List[str]:
    """Generate questions an analyst should ask."""
    questions = []
    
    # Generic questions based on input content
    input_lower = input_text.lower()
    
    if any(word in input_lower for word in ["ssh", "rdp", "remote"]):
        questions.append("What is the source IP address of the remote connection?")
    
    if any(word in input_lower for word in ["failed", "login", "authentication"]):
        questions.append("How many failed attempts occurred and from which IPs?")
        questions.append("Was MFA enabled for the targeted account?")
    
    if any(word in input_lower for word in ["DNS", "domain", "query"]):
        questions.append("What domains were queried and are they known to be malicious?")
        questions.append("What is the frequency of DNS queries to suspicious domains?")
    
    if any(word in input_lower for word in ["file", "write", "modify", "create"]):
        questions.append("What files were created or modified?")
        questions.append("Who performed the file operation?")
    
    if any(word in input_lower for word in ["process", "execute", "command", "script"]):
        questions.append("What process was executed and with what parameters?")
        questions.append("What user context was the process running under?")
    
    # Add tactic-specific questions
    if tactic:
        tactic_questions = {
            "Initial Access": [
                "What was the initial attack vector?",
                "Were there any preceding reconnaissance activities?"
            ],
            "Execution": [
                "What command or script was executed?",
                "What triggered the execution?"
            ],
            "Persistence": [
                "What persistence mechanism was established?",
                "When was the persistence mechanism created?"
            ],
            "Privilege Escalation": [
                "What privileges were escalated to?",
                "What vulnerability or misconfiguration was exploited?"
            ],
            "Defense Evasion": [
                "What security tools were targeted?",
                "What evasion technique was used?"
            ],
            "Credential Access": [
                "What credentials were accessed?",
                "How were the credentials obtained?"
            ],
            "Discovery": [
                "What information was discovered?",
                "What commands were used for discovery?"
            ],
            "Lateral Movement": [
                "What systems were accessed laterally?",
                "What credentials were used for lateral movement?"
            ],
            "Collection": [
                "What data was collected?",
                "Where was the collected data staged?"
            ],
            "Command and Control": [
                "What C2 infrastructure is being used?",
                "What protocol is used for C2 communication?"
            ],
            "Exfiltration": [
                "What data was exfiltrated?",
                "What method was used for exfiltration?"
            ],
            "Impact": [
                "What was the impact of the attack?",
                "What systems or data were affected?"
            ],
        }
        if tactic in tactic_questions:
            for q in tactic_questions[tactic]:
                if q not in questions:
                    questions.append(q)
    
    # If no specific questions, add generic ones
    if not questions:
        questions = [
            "What is the source of this activity?",
            "What is the scope and impact?",
            "What other systems might be affected?",
            "What defensive measures are currently in place?"
        ]
    
    return questions


def analyse_input(input_text: str) -> Dict:
    """
    Main function to analyse security observation input.
    
    Args:
        input_text: The security observation to analyse
        
    Returns:
        Dictionary with the analysis results
    """
    # Check for prompt injection
    if is_prompt_injection(input_text):
        return {
            "summary": "Input contains prompt injection attempt",
            "tactic": None,
            "technique_id": None,
            "evidence": [input_text[:100] + "..." if len(input_text) > 100 else input_text],
            "confidence": "low",
            "why_not": "Input appears to be a prompt injection attempt. User input is treated as untrusted.",
            "detection_idea": None,
            "network_investigation": None,
            "remediation": "Do not trust user input. Treat all input as potentially malicious.",
            "analyst_questions": [
                "What is the intent behind this input?",
                "Is this a legitimate security observation?"
            ]
        }
    
    # Handle empty input
    if not input_text or not input_text.strip():
        return {
            "summary": "Empty input provided",
            "tactic": None,
            "technique_id": None,
            "evidence": [],
            "confidence": "low",
            "why_not": "Input is empty or unparseable",
            "detection_idea": None,
            "network_investigation": None,
            "remediation": "Provide valid security observation input",
            "analyst_questions": ["What security observation needs to be analyzed?"]
        }
    
    # Find the best match
    tactic, technique_id, evidence_fragments, confidence = find_best_match(input_text)
    
    # Generate summary
    summary = generate_summary(input_text, tactic, technique_id)
    
    # Generate detection idea
    detection_idea = generate_detection_idea(tactic, technique_id)
    
    # Generate network investigation
    network_investigation = generate_network_investigation(tactic, technique_id, input_text)
    
    # Generate remediation
    remediation = generate_remediation(tactic, technique_id)
    
    # Generate analyst questions
    analyst_questions = generate_analyst_questions(input_text, tactic, technique_id)
    
    # Build why_not field
    why_not = None
    if not tactic or not technique_id:
        why_not = "Insufficient evidence to map to a specific MITRE ATT&CK tactic or technique"
    elif confidence == "low":
        why_not = "Mapping is speculative due to limited evidence"
    
    # Format technique_id with name if available
    formatted_technique_id = technique_id
    if tactic and technique_id:
        technique_name = ATTACK_FRAMEWORK.get(tactic, {}).get(technique_id, ("",))[0]
        if technique_name:
            formatted_technique_id = f"{technique_id} ({technique_name})"
    
    result = {
        "summary": summary,
        "tactic": tactic,
        "technique_id": formatted_technique_id,
        "evidence": evidence_fragments,
        "confidence": confidence,
        "why_not": why_not,
        "detection_idea": detection_idea,
        "network_investigation": network_investigation,
        "remediation": remediation,
        "analyst_questions": analyst_questions
    }
    
    return result
