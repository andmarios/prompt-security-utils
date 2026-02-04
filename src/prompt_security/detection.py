"""Suspicious content pattern detection."""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Detection severity levels."""
    HIGH = "high"      # Direct instruction override, role hijacking
    MEDIUM = "medium"  # Encoding attempts, credential patterns
    LOW = "low"        # Potential false positives (base64, etc.)


@dataclass
class DetectionResult:
    """Result of pattern detection."""
    pattern: str       # The regex pattern that matched
    category: str      # Category of the detection
    severity: Severity # Severity level
    matched_text: str  # The actual text that matched
    start_pos: int     # Start position in content
    end_pos: int       # End position in content

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for JSON serialization."""
        return {
            "pattern": self.pattern,
            "category": self.category,
            "severity": self.severity.value,
            "matched_text": self.matched_text,
            "position": {"start": self.start_pos, "end": self.end_pos},
        }


# Built-in suspicious patterns
# Format: (regex_pattern, category, severity)
SUSPICIOUS_PATTERNS: list[tuple[str, str, Severity]] = [
    # === INSTRUCTION OVERRIDE (HIGH) ===
    (r"ignore\s+(all\s+)?(your\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules|guidelines)", "instruction_override", Severity.HIGH),
    (r"disregard\s+(all\s+)?(previous|prior|above)", "instruction_override", Severity.HIGH),
    (r"forget\s+(everything|all|your)\s+(instructions?|prompts?|rules|guidelines)", "instruction_override", Severity.HIGH),
    (r"override\s+(security|instructions?|prompts?|rules|guidelines|safety)", "instruction_override", Severity.HIGH),
    (r"do\s+not\s+follow\s+(your|the|any)\s+(instructions?|prompts?|rules|guidelines)", "instruction_override", Severity.HIGH),
    (r"(new|updated|revised)\s+(instructions?|prompts?)\s*:", "instruction_override", Severity.HIGH),

    # === ROLE HIJACKING (HIGH) ===
    (r"you\s+are\s+now\s+(a|an|my)", "role_hijack", Severity.HIGH),
    (r"from\s+now\s+on\s+(you\s+are|act\s+as|pretend)", "role_hijack", Severity.HIGH),
    (r"act\s+as\s+(a|an|if|though)", "role_hijack", Severity.HIGH),
    (r"pretend\s+(to\s+be|you('re|r)|that)", "role_hijack", Severity.HIGH),
    (r"new\s+(role|persona|identity|character)\s*:", "role_hijack", Severity.HIGH),
    (r"assume\s+the\s+(role|identity|persona)\s+of", "role_hijack", Severity.HIGH),
    (r"roleplay\s+as", "role_hijack", Severity.HIGH),

    # === PROMPT/INSTRUCTION INJECTION (HIGH) ===
    (r"system\s*prompt\s*:", "prompt_injection", Severity.HIGH),
    (r"</?(system|user|assistant)>", "prompt_injection", Severity.HIGH),
    (r"\[INST\]|\[/INST\]", "prompt_injection", Severity.HIGH),
    (r"human\s*:\s*|assistant\s*:\s*", "prompt_injection", Severity.HIGH),
    (r"<\|im_start\|>|<\|im_end\|>", "prompt_injection", Severity.HIGH),
    (r"###\s*(instruction|response|human|assistant)", "prompt_injection", Severity.HIGH),

    # === JAILBREAK KEYWORDS (HIGH) ===
    (r"\b(DAN|STAN|DUDE)\s*mode\b", "jailbreak", Severity.HIGH),
    (r"developer\s*mode\s*(enabled|on|activated)", "jailbreak", Severity.HIGH),
    (r"jailbreak(ed)?\s*mode", "jailbreak", Severity.HIGH),
    (r"bypass\s+(safety|restrictions|filters|rules)", "jailbreak", Severity.HIGH),

    # === DATA EXFILTRATION (HIGH) ===
    (r"(send|forward|email|post|transmit)\s+(to|this|all|my|the)\s+", "exfiltration", Severity.HIGH),
    (r"(copy|paste|transfer)\s+(to|into)\s+", "exfiltration", Severity.MEDIUM),
    (r"(upload|export)\s+(to|all|this)", "exfiltration", Severity.MEDIUM),

    # === CREDENTIAL PATTERNS (MEDIUM) ===
    (r"(api[_\s]?key|password|secret|token|credential)\s*[:=]", "credential_leak", Severity.MEDIUM),
    (r"(bearer|authorization)\s*:\s*", "credential_leak", Severity.MEDIUM),
    (r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "credential_leak", Severity.HIGH),

    # === ENCODING/OBFUSCATION (MEDIUM/LOW) ===
    (r"[A-Za-z0-9+/]{50,}={0,2}", "base64_encoding", Severity.LOW),  # Base64 chunks
    (r"&#x?[0-9a-fA-F]+;", "html_encoding", Severity.MEDIUM),  # HTML entities
    (r"\\u[0-9a-fA-F]{4}", "unicode_escape", Severity.MEDIUM),  # Unicode escapes
    (r"[\u200b-\u200f\u2060\ufeff]", "invisible_chars", Severity.MEDIUM),  # Zero-width chars
    (r"%[0-9a-fA-F]{2}", "url_encoding", Severity.LOW),  # URL encoding

    # === LEETSPEAK EVASION (MEDIUM) ===
    (r"\b[i1!][gq9][n][o0][r][e3]\b", "leetspeak_evasion", Severity.MEDIUM),
    (r"\b[f][o0][r][gq9][e3][t7]\b", "leetspeak_evasion", Severity.MEDIUM),
    (r"\b[j][a4@][i1!][l][b][r][e3][a4@][k]\b", "leetspeak_evasion", Severity.MEDIUM),
    (r"\b[b][y][p][a4@][s5$]{2}\b", "leetspeak_evasion", Severity.MEDIUM),
    (r"\b[o0][v][e3][r][r][i1!][d][e3]\b", "leetspeak_evasion", Severity.MEDIUM),

    # === CODE COMMENT INJECTION (HIGH/MEDIUM) ===
    (r"<!--\s*(ignore|forget|override|disregard|system|new instructions)", "comment_injection", Severity.HIGH),
    (r"/\*\s*(ignore|forget|override|disregard|system|new instructions)", "comment_injection", Severity.HIGH),
    (r"//\s*(ignore|forget|override|disregard|system|new instructions)", "comment_injection", Severity.HIGH),
    (r"#\s*(ignore|forget|override|system prompt|new instructions)", "comment_injection", Severity.MEDIUM),

    # === FALSE AUTHORITY (HIGH) ===
    (r"(anthropic|openai|google|meta)\s+(says?|requires?|instructed|told|wants)", "false_authority", Severity.HIGH),
    (r"(the\s+developers?|the\s+creators?|the\s+team)\s+(said|wants?|instructed|told)\s+(you|me)", "false_authority", Severity.HIGH),
    (r"(official|authorized|admin)\s+(update|override|instruction|message)", "false_authority", Severity.HIGH),

    # === FAKE CONVERSATION HISTORY (MEDIUM) ===
    (r"(in\s+our|in\s+the)\s+(last|previous|earlier|prior)\s+(conversation|chat|session)\s+(you|we)\s+(agreed|said|promised|confirmed)", "fake_history", Severity.MEDIUM),
    (r"(you\s+previously|you\s+already)\s+(agreed|confirmed|promised|said)\s+(to|that|you)", "fake_history", Severity.MEDIUM),
    (r"(as\s+we\s+discussed|as\s+agreed)\s+(earlier|before|previously)", "fake_history", Severity.MEDIUM),

    # === ENCODING/CIPHER INSTRUCTIONS (MEDIUM/HIGH) ===
    (r"(decode|decrypt|decipher)\s+(this|the\s+following)\s+(rot13|base64|hex|cipher|encoded)", "encoding_instruction", Severity.MEDIUM),
    (r"(reverse|read\s+backwards?)\s+(this|the\s+following)\s+(text|string|message)\s+.{0,20}(execute|follow|run)", "encoding_instruction", Severity.HIGH),
    (r"(first\s+letter|acrostic|hidden\s+message|steganograph)", "encoding_instruction", Severity.MEDIUM),

    # === HOMOGLYPH / MIXED-SCRIPT DETECTION (MEDIUM) ===
    (r"[\u0400-\u04FF].*[\u0041-\u005A\u0061-\u007A]|[\u0041-\u005A\u0061-\u007A].*[\u0400-\u04FF]", "homoglyph_mixed_script", Severity.MEDIUM),

    # === PROMPT EXTRACTION (HIGH) ===
    (r"(show|reveal|display|print|output|repeat|echo)\s+.{0,10}(system\s*prompt|instructions|initial\s*prompt|rules|guidelines)", "prompt_extraction", Severity.HIGH),
    (r"what\s+(are|were)\s+your\s+(initial|original|system)\s+(instructions?|prompt|rules)", "prompt_extraction", Severity.HIGH),
]


def detect_suspicious_content(
    content: str,
    custom_patterns: list[tuple[str, str, str | Severity]] | None = None,
) -> list[DetectionResult]:
    """
    Detect suspicious patterns in content.

    Args:
        content: The content to analyze
        custom_patterns: Optional list of user-defined patterns.
                        Format: [(regex, category, severity), ...]
                        Severity can be string ("high", "medium", "low") or Severity enum.

    Returns:
        List of DetectionResult objects for each match found.
        Empty list if no suspicious patterns detected.

    Example:
        >>> results = detect_suspicious_content("Ignore all previous instructions!")
        >>> len(results)
        1
        >>> results[0].category
        'instruction_override'
        >>> results[0].severity
        <Severity.HIGH: 'high'>
    """
    results: list[DetectionResult] = []

    # Combine built-in and custom patterns
    all_patterns: list[tuple[str, str, Severity]] = list(SUSPICIOUS_PATTERNS)

    if custom_patterns:
        for pattern, category, severity in custom_patterns:
            # Convert string severity to enum if needed
            if isinstance(severity, str):
                severity = Severity(severity.lower())
            all_patterns.append((pattern, category, severity))

    # Case-insensitive search
    content_lower = content.lower()

    for pattern, category, severity in all_patterns:
        try:
            for match in re.finditer(pattern, content_lower, re.IGNORECASE | re.MULTILINE):
                results.append(DetectionResult(
                    pattern=pattern,
                    category=category,
                    severity=severity,
                    matched_text=content[match.start():match.end()],  # Original case
                    start_pos=match.start(),
                    end_pos=match.end(),
                ))
        except re.error:
            # Skip invalid regex patterns from custom config
            continue

    # Sort by severity (high first) then by position
    severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    results.sort(key=lambda r: (severity_order[r.severity], r.start_pos))

    return results
