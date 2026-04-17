import asyncio
import json
import random
from typing import AsyncGenerator

from config import settings

# ── Mock responses keyed by alert_type ───────────────────────────────────────

MOCK_RESULTS: dict[str, dict] = {
    "login_failure": {
        "threat_type": "brute_force",
        "severity_score": 8.2,
        "confidence": 0.93,
        "summary": (
            "47 authentication failures in 5 minutes originating from a known Tor "
            "exit node in Belarus (185.220.101.47) targeting the corporate VPN. "
            "The libcurl user-agent and sequential username enumeration strongly "
            "indicate an automated credential-stuffing tool. Immediate action required."
        ),
        "key_findings": [
            "47 failures in 300 seconds from single IP (rate: 9.4/min)",
            "Source IP 185.220.101.47 listed in AbuseIPDB with 1,200+ reports",
            "User-agent 'libcurl/7.81.0' is consistent with Hydra / automated tooling",
            "Multiple usernames attempted: john.doe, j.doe, johndoe, admin",
            "No successful authentications — likely pre-credential-stuffing phase",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Block 185.220.101.47 at the perimeter firewall immediately",
                "rationale": "Stop ongoing attack and prevent potential success",
            },
            {
                "step": 2,
                "action": "Force password reset for all attempted usernames",
                "rationale": "Credentials may have been obtained from a prior breach dump",
            },
            {
                "step": 3,
                "action": "Enable MFA on VPN for all accounts if not already enforced",
                "rationale": "Renders credential stuffing ineffective even if passwords are known",
            },
            {
                "step": 4,
                "action": "Search SIEM for any successful logins from this subnet in the past 30 days",
                "rationale": "Attacker may have already gained access in a prior campaign",
            },
        ],
        "iocs": ["185.220.101.47", "libcurl/7.81.0", "Tor exit node — Minsk Belarus"],
        "mitre_tactics": [
            "T1110 — Brute Force",
            "T1110.003 — Password Spraying",
            "T1078 — Valid Accounts",
        ],
        "recommendation": "escalate",
        "estimated_risk": "high",
    },
    "malware_detection": {
        "threat_type": "malware",
        "severity_score": 9.4,
        "confidence": 0.97,
        "summary": (
            "A trojan (Trojan.GenericKD.47392817) was detected on WKSTN-0042 "
            "belonging to mary.smith. The malware was delivered via a phishing "
            "attachment opened in Outlook, dropped a fake svchost.exe in the Temp "
            "directory, and immediately established a reverse shell to 192.168.100.5:4444 "
            "— a classic Cobalt Strike or Metasploit C2 pattern."
        ),
        "key_findings": [
            "svchost.exe executing from C:\\Users\\msmith\\AppData\\Local\\Temp\\ (abnormal path)",
            "Parent process outlook.exe → child svchost.exe indicates phishing delivery",
            "Active outbound connection to 192.168.100.5:4444 (known C2 port)",
            "Secondary C2 channel to 10.10.10.1:8080 suggests redundant beacon",
            "SHA-256 hash matches known Cobalt Strike stager in VirusTotal (62/72 engines)",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Isolate WKSTN-0042 from the network immediately (EDR quarantine)",
                "rationale": "Prevent lateral movement and ongoing C2 communication",
            },
            {
                "step": 2,
                "action": "Block 192.168.100.5 and 10.10.10.1 at the firewall",
                "rationale": "Cut C2 channels — these IPs are not legitimate internal assets",
            },
            {
                "step": 3,
                "action": "Collect full memory dump and disk image before remediation",
                "rationale": "Preserve forensic evidence; malware may have in-memory components",
            },
            {
                "step": 4,
                "action": "Review mary.smith's email for the phishing message and extract IOCs",
                "rationale": "Identify sender, domain, and any other recipients to scope the campaign",
            },
        ],
        "iocs": [
            "192.168.100.5:4444",
            "10.10.10.1:8080",
            "d41d8cd98f00b204e9800998ecf8427e (MD5)",
            "C:\\Users\\msmith\\AppData\\Local\\Temp\\svchost.exe",
            "Trojan.GenericKD.47392817",
        ],
        "mitre_tactics": [
            "T1566 — Phishing",
            "T1055 — Process Injection",
            "T1071 — Application Layer Protocol",
            "T1059 — Command and Scripting Interpreter",
        ],
        "recommendation": "escalate",
        "estimated_risk": "critical",
    },
    "data_exfiltration": {
        "threat_type": "insider_threat",
        "severity_score": 8.8,
        "confidence": 0.89,
        "summary": (
            "bob.johnson transferred 2 GB of sensitive files (Customer-Database.csv, "
            "Employee-Salaries.xlsx, Q4-Financial-Report.xlsx) to an external domain "
            "resembling a file-sharing service. Critically, the user submitted a "
            "resignation notice 5 days ago — this strongly suggests deliberate data "
            "theft by a departing employee."
        ),
        "key_findings": [
            "2 GB exfiltrated — 41x above the user's normal daily upload baseline (50 MB)",
            "Destination domain 'dropbox-secure-sync.net' is NOT legitimate Dropbox",
            "User accessed HR salary data despite being a junior analyst (unauthorised)",
            "USB drive inserted at 17:50 the previous day — possible local staging",
            "Resignation submitted 2026-04-10 — classic pre-departure data theft window",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Revoke bob.johnson's access to all systems immediately",
                "rationale": "Prevent further exfiltration; user is in notice period",
            },
            {
                "step": 2,
                "action": "Preserve USB forensics — image the device if still available",
                "rationale": "Determine if data was copied to physical media as well",
            },
            {
                "step": 3,
                "action": "Contact Legal / HR to initiate IP theft investigation",
                "rationale": "Customer database and financial data may constitute trade secrets",
            },
            {
                "step": 4,
                "action": "Sinkhole dropbox-secure-sync.net at DNS to identify other victims",
                "rationale": "Other employees may have been phished or have uploaded to same domain",
            },
        ],
        "iocs": [
            "dropbox-secure-sync.net",
            "203.0.113.42",
            "C:\\HR\\Employee-Salaries.xlsx",
            "C:\\Projects\\Customer-Database.csv",
        ],
        "mitre_tactics": [
            "T1052 — Exfiltration Over Physical Medium",
            "T1567 — Exfiltration Over Web Service",
            "T1078 — Valid Accounts",
        ],
        "recommendation": "escalate",
        "estimated_risk": "critical",
    },
    "lateral_movement": {
        "threat_type": "lateral_movement",
        "severity_score": 8.5,
        "confidence": 0.88,
        "summary": (
            "A service account on SERVER-WEB-01 made 28 SMB connections to 6 different "
            "internal hosts in 15 minutes — 14x above baseline. Tool signatures for "
            "PsExec and WMIC were detected, and access to ADMIN$, C$, and IPC$ shares "
            "indicates an attacker is using a compromised service account to propagate "
            "through the network."
        ),
        "key_findings": [
            "28 SMB connections in 15 min vs. baseline of 2 — 14x anomaly",
            "Targets span three subnets: 10.0.1.x, 10.0.2.x, 10.0.3.x",
            "Admin share access (ADMIN$, C$) requires privileged credentials",
            "PsExec and WMIC signatures indicate remote code execution capability",
            "SERVICE_ACCOUNT credential used — likely harvested after initial compromise",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Disable service_account and reset its password immediately",
                "rationale": "Credential is actively being used for lateral movement",
            },
            {
                "step": 2,
                "action": "Isolate SERVER-WEB-01 — the likely patient-zero pivot point",
                "rationale": "Attacker's current base of operations must be contained",
            },
            {
                "step": 3,
                "action": "Check all 6 target hosts for new scheduled tasks, services, or user accounts",
                "rationale": "Attacker may have established persistence on each traversed host",
            },
            {
                "step": 4,
                "action": "Run Tier-0 AD sweep for unexpected privilege escalations in the past 48h",
                "rationale": "Service account lateral movement often precedes domain compromise",
            },
        ],
        "iocs": [
            "10.0.1.101", "10.0.1.102", "10.0.2.10", "10.0.3.5",
            "psexec.exe", "wmic.exe remote execution",
        ],
        "mitre_tactics": [
            "T1021.002 — SMB/Windows Admin Shares",
            "T1570 — Lateral Tool Transfer",
            "T1047 — Windows Management Instrumentation",
        ],
        "recommendation": "escalate",
        "estimated_risk": "critical",
    },
    "anomalous_behavior": {
        "threat_type": "anomaly",
        "severity_score": 6.5,
        "confidence": 0.82,
        "summary": (
            "alice.wong authenticated from San Francisco at 01:30 UTC and then from "
            "Moscow 135 minutes later — a physical impossibility (9,365 km at 4,162 km/h). "
            "The Moscow session originated from a Tor exit node on a new device fingerprint. "
            "This strongly suggests account compromise, though a VPN misconfiguration "
            "cannot be fully excluded."
        ),
        "key_findings": [
            "Travel speed required: 4,162 km/h — physically impossible",
            "Moscow session originated from confirmed Tor exit node",
            "New device fingerprint — not a registered device for this user",
            "No VPN detected on the Moscow session",
            "Previous logins consistently from San Francisco on known device",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Terminate the active Moscow session and force re-authentication",
                "rationale": "If compromised, attacker has live access right now",
            },
            {
                "step": 2,
                "action": "Contact alice.wong directly to verify if she initiated the login",
                "rationale": "Confirm or rule out legitimate use (e.g., travel VPN misconfiguration)",
            },
            {
                "step": 3,
                "action": "Review alice.wong's actions in the Moscow session (API calls, data access)",
                "rationale": "Determine if attacker has already exfiltrated data or made changes",
            },
        ],
        "iocs": ["185.220.101.90", "Tor exit node — Moscow Russia", "new_device_fingerprint"],
        "mitre_tactics": [
            "T1078 — Valid Accounts",
            "T1133 — External Remote Services",
            "T1090 — Proxy (Tor)",
        ],
        "recommendation": "monitor",
        "estimated_risk": "medium",
    },
    "c2_communication": {
        "threat_type": "c2_communication",
        "severity_score": 9.6,
        "confidence": 0.96,
        "summary": (
            "DNS tunnelling C2 traffic attributed to APT28 (Fancy Bear) was detected "
            "from charlie.brown's workstation. The process chrome.exe is generating "
            "1,847 DNS queries/hour with entropy 4.8 to a known APT28 C2 domain. "
            "An estimated 512 KB of data has already been exfiltrated covertly. "
            "This is a nation-state level intrusion."
        ),
        "key_findings": [
            "1,847 DNS queries/hour vs. baseline 120 — 15x anomaly",
            "Query entropy 4.8 (threshold: 3.5) — data encoded in subdomains",
            "Domain a1b2c3d4e5f6.evil-c2-server.xyz in APT28 known C2 list (Mandiant)",
            "~512 KB exfiltrated covertly via DNS — likely credentials or documents",
            "APT28 attribution — Russian GRU-linked threat actor (MITRE G0007)",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Isolate WKSTN-0088 immediately and sinkhole the C2 domain at DNS",
                "rationale": "Nation-state implant — assume full system compromise",
            },
            {
                "step": 2,
                "action": "Escalate to CISA / FBI under nation-state incident reporting obligations",
                "rationale": "APT28 intrusions may require federal notification",
            },
            {
                "step": 3,
                "action": "Full forensic acquisition: memory, disk, network logs from WKSTN-0088",
                "rationale": "Determine dwell time, persistence mechanisms, and full data scope",
            },
            {
                "step": 4,
                "action": "Sweep all hosts for the same chrome.exe DNS pattern",
                "rationale": "APT28 campaigns typically target multiple hosts simultaneously",
            },
        ],
        "iocs": [
            "a1b2c3d4e5f6.evil-c2-server.xyz",
            "10.0.4.88",
            "APT28 / Fancy Bear",
            "chrome.exe PID 4892",
        ],
        "mitre_tactics": [
            "T1071.004 — DNS C2",
            "T1048 — Exfiltration Over Alternative Protocol",
            "T1027 — Obfuscated Files or Information",
        ],
        "recommendation": "escalate",
        "estimated_risk": "critical",
    },
    "privilege_escalation": {
        "threat_type": "privilege_escalation",
        "severity_score": 8.0,
        "confidence": 0.91,
        "summary": (
            "dave.miller escalated from standard user to SYSTEM via token impersonation "
            "exploiting CVE-2023-44487. The attacker added themselves to the local "
            "Administrators group, modified the Winlogon registry key for persistence, "
            "and ran 'whoami /priv' — a textbook post-exploitation enumeration sequence."
        ),
        "key_findings": [
            "Token impersonation via CVE-2023-44487 — unpatched vulnerability",
            "Net localgroup administrators modified — persistence via admin group",
            "Winlogon registry modified — potential backdoor or credential harvester",
            "'whoami /priv' executed — confirms attacker is enumerating privileges",
            "Parent process explorer.exe → cmd.exe is unusual for this user profile",
        ],
        "investigation_steps": [
            {
                "step": 1,
                "action": "Remove dave.miller from the local Administrators group immediately",
                "rationale": "Revoke the escalated privilege before further damage",
            },
            {
                "step": 2,
                "action": "Patch CVE-2023-44487 on WKSTN-0055 and all unpatched endpoints",
                "rationale": "Close the vulnerability that enabled escalation",
            },
            {
                "step": 3,
                "action": "Audit Winlogon registry key and revert any unauthorised changes",
                "rationale": "Attacker may have installed a persistent backdoor or keylogger",
            },
            {
                "step": 4,
                "action": "Interview dave.miller — determine if actions were intentional or induced by malware",
                "rationale": "Could be insider threat or a compromised user being used as a pivot",
            },
        ],
        "iocs": [
            "CVE-2023-44487",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            "net localgroup administrators dave.miller /add",
        ],
        "mitre_tactics": [
            "T1134 — Access Token Manipulation",
            "T1068 — Exploitation for Privilege Escalation",
            "T1547 — Boot or Logon Autostart Execution",
        ],
        "recommendation": "escalate",
        "estimated_risk": "high",
    },
}

_DEFAULT_RESULT = {
    "threat_type": "anomaly",
    "severity_score": 5.0,
    "confidence": 0.70,
    "summary": "Suspicious activity detected. Manual review recommended.",
    "key_findings": ["Anomalous behaviour pattern detected", "Insufficient baseline data for full correlation"],
    "investigation_steps": [
        {"step": 1, "action": "Review raw alert data in SIEM", "rationale": "Establish full context"},
        {"step": 2, "action": "Check user activity history for anomalies", "rationale": "Baseline comparison"},
    ],
    "iocs": [],
    "mitre_tactics": ["T1078 — Valid Accounts"],
    "recommendation": "monitor",
    "estimated_risk": "medium",
}

# ── System prompt ─────────────────────────────────────────────────────────────

INVESTIGATION_PROMPT = """\
You are an expert Security Operations Center (SOC) AI analyst with deep knowledge \
of threat hunting, incident response, and the MITRE ATT&CK framework.

## ALERT UNDER INVESTIGATION

Alert Type   : {alert_type}
User ID      : {user_id}
Source IP    : {source_ip}
Hostname     : {hostname}
Severity Hint: {severity_hint}
Occurred At  : {occurred_at}

Raw Alert Data:
{raw_data}

## RETRIEVED CONTEXT

### User Activity History (recent behavioural baseline):
{user_activity}

### Similar Past Alerts:
{similar_alerts}

### Relevant Threat Intelligence:
{threat_intel}

## INVESTIGATION TASK

Analyse this security alert comprehensively. Consider:
1. Pattern analysis — is this brute force, insider threat, malware C2, \
data exfiltration, lateral movement, or something else?
2. User behaviour — does the activity history show anomalies vs the baseline?
3. Threat correlation — do any IOCs or TTPs match known threat actors?
4. Risk assessment — what is the potential business impact?
5. Prioritisation — what should the analyst investigate first?

Respond with ONLY a valid JSON object in the exact format below. \
No markdown, no explanation, no code fences — pure JSON only.

{{
  "threat_type": "brute_force|insider_threat|malware|data_exfiltration|lateral_movement|c2_communication|privilege_escalation|anomaly|false_positive",
  "severity_score": <float 1.0–10.0>,
  "confidence": <float 0.0–1.0>,
  "summary": "<2-3 sentence executive summary>",
  "key_findings": ["<finding1>", "<finding2>", "<finding3>"],
  "investigation_steps": [
    {{"step": 1, "action": "<specific action>", "rationale": "<why>"}},
    {{"step": 2, "action": "<specific action>", "rationale": "<why>"}},
    {{"step": 3, "action": "<specific action>", "rationale": "<why>"}}
  ],
  "iocs": ["<ip/hash/domain/username>"],
  "mitre_tactics": ["<T-code — tactic name>"],
  "recommendation": "escalate|monitor|ignore",
  "estimated_risk": "critical|high|medium|low"
}}"""


# ── Service class ─────────────────────────────────────────────────────────────


def _is_mock_mode() -> bool:
    key = settings.OPENAI_API_KEY or ""
    return not key or key.startswith("sk-your") or key == "sk-placeholder"


class LLMService:
    def __init__(self) -> None:
        self._llm = None
        self._chain = None

    def _ensure_chain(self) -> None:
        """Lazily initialise the LangChain LCEL chain on first use."""
        if self._chain is None:
            from langchain_core.output_parsers import StrOutputParser
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_openai import ChatOpenAI

            self._llm = ChatOpenAI(
                model=settings.OPENAI_MODEL,
                temperature=0,
                streaming=True,
                api_key=settings.OPENAI_API_KEY,
            )
            prompt = ChatPromptTemplate.from_template(INVESTIGATION_PROMPT)
            self._chain = prompt | self._llm | StrOutputParser()

    @staticmethod
    def _format_context(items: list[dict]) -> str:
        if not items:
            return "No relevant data found."
        lines = []
        for i, item in enumerate(items, 1):
            lines.append(f"{i}. {item['content']}")
        return "\n".join(lines)

    async def investigate_stream(
        self, alert, context: dict
    ) -> AsyncGenerator[str, None]:
        """Stream investigation result — mock mode when no real API key."""
        if _is_mock_mode():
            async for chunk in self._mock_stream(alert):
                yield chunk
            return

        self._ensure_chain()

        inputs = {
            "alert_type": alert.alert_type,
            "user_id": alert.user_id or "unknown",
            "source_ip": alert.source_ip or "unknown",
            "hostname": alert.hostname or "unknown",
            "severity_hint": alert.severity_hint or "unknown",
            "occurred_at": (
                alert.occurred_at.isoformat() if alert.occurred_at else "unknown"
            ),
            "raw_data": json.dumps(alert.raw_data, indent=2),
            "user_activity": self._format_context(context.get("user_activity", [])),
            "similar_alerts": self._format_context(context.get("similar_alerts", [])),
            "threat_intel": self._format_context(context.get("threat_intel", [])),
        }

        async for chunk in self._chain.astream(inputs):
            yield chunk

    async def _mock_stream(self, alert) -> AsyncGenerator[str, None]:
        """Stream pre-written JSON for the alert type, character by character."""
        result = MOCK_RESULTS.get(alert.alert_type, _DEFAULT_RESULT).copy()
        # Personalise with live alert fields where possible
        if alert.user_id:
            result["summary"] = result["summary"].replace(
                next(
                    (n for n in ["bob.johnson", "alice.wong", "charlie.brown",
                                 "dave.miller", "mary.smith", "john.doe"]
                     if n in result["summary"]),
                    ""
                ),
                alert.user_id,
            )
        text = json.dumps(result, indent=2)
        chunk_size = 4
        for i in range(0, len(text), chunk_size):
            yield text[i: i + chunk_size]
            await asyncio.sleep(0.015)


llm_service = LLMService()
