"""
PII Detection engine for wiretaps.

Detects sensitive data patterns in text including:
- Personal identifiers (email, phone, SSN, CPF)
- Financial data (credit cards, bank accounts)
- Crypto data (wallet addresses, private keys, seed phrases)
"""

import re
from dataclasses import dataclass


@dataclass
class PIIMatch:
    """A detected PII match."""

    pattern_name: str
    matched_text: str
    start: int
    end: int
    severity: str = "medium"  # low, medium, high, critical


# BIP-39 wordlist (first 100 words for detection)
BIP39_WORDS = {
    "abandon",
    "ability",
    "able",
    "about",
    "above",
    "absent",
    "absorb",
    "abstract",
    "absurd",
    "abuse",
    "access",
    "accident",
    "account",
    "accuse",
    "achieve",
    "acid",
    "acoustic",
    "acquire",
    "across",
    "act",
    "action",
    "actor",
    "actress",
    "actual",
    "adapt",
    "add",
    "addict",
    "address",
    "adjust",
    "admit",
    "adult",
    "advance",
    "advice",
    "aerobic",
    "affair",
    "afford",
    "afraid",
    "again",
    "age",
    "agent",
    "agree",
    "ahead",
    "aim",
    "air",
    "airport",
    "aisle",
    "alarm",
    "album",
    "alcohol",
    "alert",
    "alien",
    "all",
    "alley",
    "allow",
    "almost",
    "alone",
    "alpha",
    "already",
    "also",
    "alter",
    "always",
    "amateur",
    "amazing",
    "among",
    "amount",
    "amused",
    "analyst",
    "anchor",
    "ancient",
    "anger",
    "angle",
    "angry",
    "animal",
    "ankle",
    "announce",
    "annual",
    "another",
    "answer",
    "antenna",
    "antique",
    "anxiety",
    "any",
    "apart",
    "apology",
    "appear",
    "apple",
    "approve",
    "april",
    "arch",
    "arctic",
    "area",
    "arena",
    "argue",
    "arm",
    "armed",
    "armor",
    "army",
    "around",
    "arrange",
    "arrest",
}


class PIIPatterns:
    """Built-in PII detection patterns."""

    # Personal identifiers
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    # Phone: must start with + or have parentheses/dashes (to avoid matching plain numbers)
    PHONE_INTL = re.compile(
        r"(?:\+[1-9]\d{0,2}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}|\(\d{2,4}\)[-.\s]?\d{4,5}[-.\s]?\d{4})"
    )

    SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # Brazilian CPF
    CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")

    # Brazilian CNPJ
    CNPJ = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")

    # Financial
    CREDIT_CARD = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    )

    CREDIT_CARD_FORMATTED = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

    # Crypto
    BTC_ADDRESS = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")

    ETH_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

    PRIVATE_KEY_HEX = re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b")

    # API Keys / Secrets (common patterns)
    API_KEY_GENERIC = re.compile(
        r"\b(?:sk|pk|api|key|secret|token|auth|bearer)[-_]?[a-zA-Z0-9]{20,}\b", re.IGNORECASE
    )

    OPENAI_KEY = re.compile(r"\bsk-[a-zA-Z0-9]{48}\b")

    ANTHROPIC_KEY = re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{50,}\b")


class PIIDetector:
    """
    Detects PII and sensitive data in text.

    Usage:
        detector = PIIDetector()
        matches = detector.scan("Contact me at user@example.com")
    """

    def __init__(self, custom_patterns: list[dict] | None = None):
        self.patterns = [
            ("email", PIIPatterns.EMAIL, "medium"),
            ("phone", PIIPatterns.PHONE_INTL, "medium"),
            ("ssn", PIIPatterns.SSN, "critical"),
            ("cpf", PIIPatterns.CPF, "high"),
            ("cnpj", PIIPatterns.CNPJ, "medium"),
            ("credit_card", PIIPatterns.CREDIT_CARD, "critical"),
            ("credit_card", PIIPatterns.CREDIT_CARD_FORMATTED, "critical"),
            ("btc_address", PIIPatterns.BTC_ADDRESS, "high"),
            ("eth_address", PIIPatterns.ETH_ADDRESS, "high"),
            ("private_key", PIIPatterns.PRIVATE_KEY_HEX, "critical"),
            ("api_key", PIIPatterns.API_KEY_GENERIC, "critical"),
            ("openai_key", PIIPatterns.OPENAI_KEY, "critical"),
            ("anthropic_key", PIIPatterns.ANTHROPIC_KEY, "critical"),
        ]

        # Add custom patterns
        if custom_patterns:
            for p in custom_patterns:
                self.patterns.append(
                    (p["name"], re.compile(p["regex"]), p.get("severity", "medium"))
                )

    def scan(self, text: str) -> list[PIIMatch]:
        """
        Scan text for PII patterns.

        Args:
            text: Text to scan

        Returns:
            List of PIIMatch objects for detected PII
        """
        matches = []

        # Run regex patterns
        for name, pattern, severity in self.patterns:
            for match in pattern.finditer(text):
                # Avoid duplicate matches at same position
                if not any(m.start == match.start() and m.end == match.end() for m in matches):
                    matches.append(
                        PIIMatch(
                            pattern_name=name,
                            matched_text=match.group(),
                            start=match.start(),
                            end=match.end(),
                            severity=severity,
                        )
                    )

        # Check for seed phrases (12 or 24 BIP-39 words)
        seed_matches = self._detect_seed_phrase(text)
        matches.extend(seed_matches)

        return matches

    def _detect_seed_phrase(self, text: str) -> list[PIIMatch]:
        """Detect potential BIP-39 seed phrases."""
        matches = []
        words = text.lower().split()

        # Look for sequences of 12 or 24 BIP-39 words
        for length in [12, 24]:
            if len(words) < length:
                continue

            for i in range(len(words) - length + 1):
                sequence = words[i : i + length]
                bip39_count = sum(1 for w in sequence if w in BIP39_WORDS)

                # If >80% are BIP-39 words, likely a seed phrase
                if bip39_count / length > 0.8:
                    phrase = " ".join(sequence)
                    start = text.lower().find(phrase)
                    if start >= 0:
                        matches.append(
                            PIIMatch(
                                pattern_name="seed_phrase",
                                matched_text=phrase[:50] + "...",  # Truncate for safety
                                start=start,
                                end=start + len(phrase),
                                severity="critical",
                            )
                        )

        return matches

    def has_pii(self, text: str) -> bool:
        """Quick check if text contains any PII."""
        return len(self.scan(text)) > 0

    def get_pii_types(self, text: str) -> list[str]:
        """Get list of PII types found in text."""
        matches = self.scan(text)
        return list({m.pattern_name for m in matches})

    def redact(self, text: str, replacement: str = "[REDACTED]") -> str:
        """
        Redact PII from text.

        Args:
            text: Text to redact
            replacement: Replacement string for PII

        Returns:
            Text with PII replaced
        """
        matches = self.scan(text)

        # Sort by position (reverse) to replace from end to start
        matches.sort(key=lambda m: m.start, reverse=True)

        result = text
        for match in matches:
            result = result[: match.start] + replacement + result[match.end :]

        return result
