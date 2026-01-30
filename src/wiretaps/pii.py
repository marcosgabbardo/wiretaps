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
    """Built-in PII detection patterns for global coverage."""

    # ==================== UNIVERSAL ====================
    EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

    # Phone: international format with + or parentheses
    PHONE_INTL = re.compile(
        r"(?:\+[1-9]\d{0,2}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}|\(\d{2,4}\)[-.\s]?\d{4,5}[-.\s]?\d{4})"
    )

    # US Phone (XXX) XXX-XXXX or XXX-XXX-XXXX
    PHONE_US = re.compile(r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")

    # UK Phone (starts with 0, 10-11 digits)
    PHONE_UK = re.compile(r"\b0\d{2,4}[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b")

    # ==================== IP ADDRESSES ====================
    # IPv4
    IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    # IPv6 (simplified - catches most formats)
    IPV6 = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")

    # ==================== POSTAL CODES ====================
    # US ZIP Code (5 digits or 5+4)
    US_ZIP = re.compile(r"\b\d{5}(?:-\d{4})?\b")

    # UK Postcode (e.g., SW1A 1AA, M1 1AE)
    UK_POSTCODE = re.compile(
        r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b", re.IGNORECASE
    )

    # Brazilian CEP (XXXXX-XXX)
    BR_CEP = re.compile(r"\b\d{5}-?\d{3}\b")

    # German PLZ (5 digits)
    DE_PLZ = re.compile(r"\b\d{5}\b")

    # French Code Postal (5 digits)
    FR_CP = re.compile(r"\b\d{5}\b")

    # Canadian Postal Code (A1A 1A1)
    CA_POSTAL = re.compile(r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b", re.IGNORECASE)

    # Australian Postcode (4 digits)
    AU_POSTCODE = re.compile(r"\b\d{4}\b")

    # ==================== PHYSICAL ADDRESS PATTERNS ====================
    # US/UK style: number + street name (123 Main Street)
    STREET_ADDRESS_US = re.compile(
        r"\b\d{1,5}\s+[\w\s]{1,30}\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|drive|dr|lane|ln|way|court|ct|place|pl|circle|cir|terrace|ter|highway|hwy)\b",
        re.IGNORECASE
    )

    # Brazilian/Latin style: street name + number (Rua das Flores, 456)
    STREET_ADDRESS_BR = re.compile(
        r"(?:rua|avenida|av|alameda|travessa|estrada|calle|carrera)\s+[\w\s]+[,\s]+\d+",
        re.IGNORECASE
    )

    # PO Box
    PO_BOX = re.compile(r"\b(?:p\.?o\.?\s*box|caixa\s*postal|apartado)\s*\d+\b", re.IGNORECASE)

    # ==================== AMERICAS ====================
    # US Social Security Number (XXX-XX-XXXX)
    US_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

    # US Individual Taxpayer Identification Number (9XX-XX-XXXX)
    US_ITIN = re.compile(r"\b9\d{2}-\d{2}-\d{4}\b")

    # Canadian Social Insurance Number (XXX-XXX-XXX)
    CA_SIN = re.compile(r"\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b")

    # Brazilian CPF (XXX.XXX.XXX-XX)
    BR_CPF = re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b")

    # Brazilian CNPJ (XX.XXX.XXX/XXXX-XX)
    BR_CNPJ = re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b")

    # Mexican CURP (18 alphanumeric)
    MX_CURP = re.compile(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b")

    # Mexican RFC (12-13 alphanumeric)
    MX_RFC = re.compile(r"\b[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}\b")

    # ==================== EUROPE ====================
    # UK National Insurance Number (AB123456C)
    UK_NIN = re.compile(
        r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b", re.IGNORECASE
    )

    # German ID/Passport Number (9 alphanumeric)
    DE_ID = re.compile(r"\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b")

    # French INSEE/NIR (15 digits, social security)
    FR_NIR = re.compile(r"\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b")

    # Spanish DNI (8 digits + letter)
    ES_DNI = re.compile(r"\b\d{8}[A-Z]\b")

    # Spanish NIE (X/Y/Z + 7 digits + letter)
    ES_NIE = re.compile(r"\b[XYZ]\d{7}[A-Z]\b")

    # Italian Codice Fiscale (16 alphanumeric)
    IT_CF = re.compile(r"\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b")

    # Portuguese NIF (9 digits)
    PT_NIF = re.compile(r"\b[125689]\d{8}\b")

    # Dutch BSN (9 digits)
    NL_BSN = re.compile(r"\b\d{9}\b")

    # Belgian National Number (YY.MM.DD-XXX.XX)
    BE_NN = re.compile(r"\b\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}\b")

    # Swiss AHV/AVS (756.XXXX.XXXX.XX)
    CH_AHV = re.compile(r"\b756\.\d{4}\.\d{4}\.\d{2}\b")

    # EU VAT Number (country code + 8-12 chars)
    EU_VAT = re.compile(
        r"\b(AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[A-Z0-9]{8,12}\b"
    )

    # ==================== ASIA-PACIFIC ====================
    # Australian Tax File Number (XXX XXX XXX)
    AU_TFN = re.compile(r"\b\d{3}\s?\d{3}\s?\d{3}\b")

    # Indian Aadhaar (12 digits, groups of 4)
    IN_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")

    # Indian PAN (AAAAA0000A)
    IN_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

    # Japanese My Number (12 digits)
    JP_MY_NUMBER = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")

    # South Korean RRN (YYMMDD-XXXXXXX)
    KR_RRN = re.compile(r"\b\d{6}-[1-4]\d{6}\b")

    # ==================== PASSPORTS ====================
    # US Passport (9 digits or alphanumeric)
    PASSPORT_US = re.compile(r"\b[A-Z]?\d{8,9}\b")

    # UK Passport (9 digits)
    PASSPORT_UK = re.compile(r"\b\d{9}\b")

    # Generic passport (2 letters + 7 digits, common format)
    PASSPORT_GENERIC = re.compile(r"\b[A-Z]{2}\d{7}\b")

    # ==================== FINANCIAL ====================
    # Credit Cards (Visa, MC, Amex, Discover)
    CREDIT_CARD = re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    )

    CREDIT_CARD_FORMATTED = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")

    # IBAN (International Bank Account Number)
    IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b")

    # SWIFT/BIC Code
    SWIFT_BIC = re.compile(r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b")

    # ==================== CRYPTO ====================
    BTC_ADDRESS = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}\b")

    ETH_ADDRESS = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

    PRIVATE_KEY_HEX = re.compile(r"\b(?:0x)?[a-fA-F0-9]{64}\b")

    # ==================== API KEYS ====================
    API_KEY_GENERIC = re.compile(
        r"\b(?:sk|pk|api|key|secret|token|auth|bearer)[-_]?[a-zA-Z0-9]{20,}\b", re.IGNORECASE
    )

    OPENAI_KEY = re.compile(r"\bsk-[a-zA-Z0-9]{48}\b")

    ANTHROPIC_KEY = re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{50,}\b")

    AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

    AWS_SECRET_KEY = re.compile(r"\b[A-Za-z0-9/+=]{40}\b")

    GITHUB_TOKEN = re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b")


class PIIDetector:
    """
    Detects PII and sensitive data in text.

    Usage:
        detector = PIIDetector()
        matches = detector.scan("Contact me at user@example.com")
    """

    def __init__(self, custom_patterns: list[dict] | None = None):
        self.patterns = [
            # Universal
            ("email", PIIPatterns.EMAIL, "medium"),
            ("phone", PIIPatterns.PHONE_INTL, "medium"),
            ("phone_us", PIIPatterns.PHONE_US, "medium"),
            ("phone_uk", PIIPatterns.PHONE_UK, "medium"),
            # IP Addresses
            ("ipv4", PIIPatterns.IPV4, "medium"),
            ("ipv6", PIIPatterns.IPV6, "medium"),
            # Postal Codes
            ("us_zip", PIIPatterns.US_ZIP, "low"),
            ("uk_postcode", PIIPatterns.UK_POSTCODE, "low"),
            ("br_cep", PIIPatterns.BR_CEP, "low"),
            ("ca_postal", PIIPatterns.CA_POSTAL, "low"),
            # Addresses
            ("street_address", PIIPatterns.STREET_ADDRESS_US, "medium"),
            ("street_address", PIIPatterns.STREET_ADDRESS_BR, "medium"),
            ("po_box", PIIPatterns.PO_BOX, "low"),
            # Americas
            ("us_ssn", PIIPatterns.US_SSN, "critical"),
            ("us_itin", PIIPatterns.US_ITIN, "critical"),
            ("ca_sin", PIIPatterns.CA_SIN, "critical"),
            ("br_cpf", PIIPatterns.BR_CPF, "high"),
            ("br_cnpj", PIIPatterns.BR_CNPJ, "medium"),
            ("mx_curp", PIIPatterns.MX_CURP, "high"),
            ("mx_rfc", PIIPatterns.MX_RFC, "medium"),
            # Europe
            ("uk_nin", PIIPatterns.UK_NIN, "critical"),
            ("de_id", PIIPatterns.DE_ID, "high"),
            ("fr_nir", PIIPatterns.FR_NIR, "critical"),
            ("es_dni", PIIPatterns.ES_DNI, "high"),
            ("es_nie", PIIPatterns.ES_NIE, "high"),
            ("it_cf", PIIPatterns.IT_CF, "high"),
            ("pt_nif", PIIPatterns.PT_NIF, "medium"),
            ("be_nn", PIIPatterns.BE_NN, "high"),
            ("ch_ahv", PIIPatterns.CH_AHV, "high"),
            ("eu_vat", PIIPatterns.EU_VAT, "medium"),
            # Asia-Pacific
            ("au_tfn", PIIPatterns.AU_TFN, "critical"),
            ("in_aadhaar", PIIPatterns.IN_AADHAAR, "critical"),
            ("in_pan", PIIPatterns.IN_PAN, "high"),
            ("kr_rrn", PIIPatterns.KR_RRN, "critical"),
            # Passports
            ("passport", PIIPatterns.PASSPORT_GENERIC, "critical"),
            # Financial
            ("credit_card", PIIPatterns.CREDIT_CARD, "critical"),
            ("credit_card", PIIPatterns.CREDIT_CARD_FORMATTED, "critical"),
            ("iban", PIIPatterns.IBAN, "high"),
            ("swift_bic", PIIPatterns.SWIFT_BIC, "medium"),
            # Crypto
            ("btc_address", PIIPatterns.BTC_ADDRESS, "high"),
            ("eth_address", PIIPatterns.ETH_ADDRESS, "high"),
            ("private_key", PIIPatterns.PRIVATE_KEY_HEX, "critical"),
            # API Keys
            ("api_key", PIIPatterns.API_KEY_GENERIC, "critical"),
            ("openai_key", PIIPatterns.OPENAI_KEY, "critical"),
            ("anthropic_key", PIIPatterns.ANTHROPIC_KEY, "critical"),
            ("aws_access_key", PIIPatterns.AWS_ACCESS_KEY, "critical"),
            ("github_token", PIIPatterns.GITHUB_TOKEN, "critical"),
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

    def redact(self, text: str, replacement: str | None = None, use_type_labels: bool = True) -> str:
        """
        Redact PII from text.

        Args:
            text: Text to redact
            replacement: Fixed replacement string (overrides type labels)
            use_type_labels: If True, use [EMAIL], [SSN], etc. instead of generic [REDACTED]

        Returns:
            Text with PII replaced
        """
        matches = self.scan(text)
        
        # Remove overlapping matches (keep longer match)
        matches = self._remove_overlaps(matches)

        # Sort by position (reverse) to replace from end to start
        matches.sort(key=lambda m: m.start, reverse=True)

        result = text
        for match in matches:
            if replacement:
                label = replacement
            elif use_type_labels:
                label = f"[{match.pattern_name.upper()}]"
            else:
                label = "[REDACTED]"
            result = result[: match.start] + label + result[match.end :]

        return result
    
    def _remove_overlaps(self, matches: list[PIIMatch]) -> list[PIIMatch]:
        """Remove overlapping matches, keeping the longer one."""
        if not matches:
            return matches
        
        # Sort by start position, then by length (descending)
        matches.sort(key=lambda m: (m.start, -(m.end - m.start)))
        
        result = []
        for match in matches:
            # Check if this match overlaps with any already accepted match
            overlaps = False
            for accepted in result:
                if not (match.end <= accepted.start or match.start >= accepted.end):
                    overlaps = True
                    break
            if not overlaps:
                result.append(match)
        
        return result

    def redact_with_map(self, text: str) -> tuple[str, dict[str, str]]:
        """
        Redact PII and return a map for potential restoration.

        Args:
            text: Text to redact

        Returns:
            Tuple of (redacted_text, map of placeholder -> original value)
        """
        matches = self.scan(text)
        matches = self._remove_overlaps(matches)
        matches.sort(key=lambda m: m.start, reverse=True)

        result = text
        redact_map = {}
        counters: dict[str, int] = {}

        for match in matches:
            ptype = match.pattern_name.upper()
            counters[ptype] = counters.get(ptype, 0) + 1
            label = f"[{ptype}_{counters[ptype]}]"
            redact_map[label] = match.matched_text
            result = result[: match.start] + label + result[match.end :]

        return result, redact_map
