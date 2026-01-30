"""Tests for PII detection."""

import pytest

from wiretaps.pii import PIIDetector


@pytest.fixture
def detector():
    return PIIDetector()


class TestEmailDetection:
    def test_simple_email(self, detector):
        matches = detector.scan("Contact me at user@example.com")
        assert len(matches) == 1
        assert matches[0].pattern_name == "email"
        assert matches[0].matched_text == "user@example.com"

    def test_multiple_emails(self, detector):
        text = "Send to alice@test.com and bob@example.org"
        matches = detector.scan(text)
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 2


class TestPhoneDetection:
    def test_us_phone(self, detector):
        matches = detector.scan("Call me at +1 (555) 123-4567")
        phones = [m for m in matches if m.pattern_name == "phone"]
        assert len(phones) >= 1

    def test_brazil_phone(self, detector):
        matches = detector.scan("WhatsApp: +55 11 99999-8888")
        phones = [m for m in matches if m.pattern_name == "phone"]
        assert len(phones) >= 1


class TestCryptoDetection:
    def test_btc_address(self, detector):
        matches = detector.scan("Send to bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
        btc = [m for m in matches if m.pattern_name == "btc_address"]
        assert len(btc) == 1

    def test_eth_address(self, detector):
        matches = detector.scan("ETH: 0x71C7656EC7ab88b098defB751B7401B5f6d8976F")
        eth = [m for m in matches if m.pattern_name == "eth_address"]
        assert len(eth) == 1

    def test_private_key(self, detector):
        # 64 hex chars = potential private key
        key = "0x" + "a" * 64
        matches = detector.scan(f"Key: {key}")
        keys = [m for m in matches if m.pattern_name == "private_key"]
        assert len(keys) == 1


class TestBrazilianPII:
    def test_cpf(self, detector):
        matches = detector.scan("CPF: 123.456.789-00")
        cpf = [m for m in matches if m.pattern_name == "br_cpf"]
        assert len(cpf) == 1

    def test_cpf_unformatted(self, detector):
        matches = detector.scan("CPF: 12345678900")
        cpf = [m for m in matches if m.pattern_name == "br_cpf"]
        assert len(cpf) == 1


class TestPhoneNumbers:
    def test_us_phone(self, detector):
        matches = detector.scan("Call me at (555) 123-4567")
        phones = [m for m in matches if "phone" in m.pattern_name]
        assert len(phones) >= 1

    def test_intl_phone(self, detector):
        matches = detector.scan("WhatsApp: +55 11 99999-8888")
        phones = [m for m in matches if "phone" in m.pattern_name]
        assert len(phones) >= 1


class TestIPAddresses:
    def test_ipv4(self, detector):
        matches = detector.scan("Server IP: 192.168.1.100")
        ips = [m for m in matches if m.pattern_name == "ipv4"]
        assert len(ips) == 1

    def test_ipv4_public(self, detector):
        matches = detector.scan("Connect to 8.8.8.8")
        ips = [m for m in matches if m.pattern_name == "ipv4"]
        assert len(ips) == 1


class TestPostalCodes:
    def test_us_zip(self, detector):
        matches = detector.scan("ZIP: 90210")
        zips = [m for m in matches if m.pattern_name == "us_zip"]
        assert len(zips) == 1

    def test_us_zip_plus4(self, detector):
        matches = detector.scan("ZIP: 90210-1234")
        zips = [m for m in matches if m.pattern_name == "us_zip"]
        assert len(zips) == 1

    def test_uk_postcode(self, detector):
        matches = detector.scan("London: SW1A 1AA")
        codes = [m for m in matches if m.pattern_name == "uk_postcode"]
        assert len(codes) == 1

    def test_brazil_cep(self, detector):
        matches = detector.scan("CEP: 01310-100")
        ceps = [m for m in matches if m.pattern_name == "br_cep"]
        assert len(ceps) == 1

    def test_canada_postal(self, detector):
        matches = detector.scan("Toronto: M5V 3L9")
        codes = [m for m in matches if m.pattern_name == "ca_postal"]
        assert len(codes) == 1


class TestAddresses:
    def test_street_address(self, detector):
        matches = detector.scan("I live at 123 Main Street")
        addrs = [m for m in matches if m.pattern_name == "street_address"]
        assert len(addrs) == 1

    def test_brazilian_address(self, detector):
        matches = detector.scan("Endereço: Rua das Flores, 456")
        addrs = [m for m in matches if m.pattern_name == "street_address"]
        assert len(addrs) == 1

    def test_po_box(self, detector):
        matches = detector.scan("Send to P.O. Box 12345")
        boxes = [m for m in matches if m.pattern_name == "po_box"]
        assert len(boxes) == 1


class TestGlobalPII:
    def test_us_ssn(self, detector):
        matches = detector.scan("SSN: 123-45-6789")
        ssn = [m for m in matches if m.pattern_name == "us_ssn"]
        assert len(ssn) == 1

    def test_uk_nin(self, detector):
        matches = detector.scan("NIN: AB123456C")
        nin = [m for m in matches if m.pattern_name == "uk_nin"]
        assert len(nin) == 1

    def test_spanish_dni(self, detector):
        matches = detector.scan("DNI: 12345678A")
        dni = [m for m in matches if m.pattern_name == "es_dni"]
        assert len(dni) == 1

    def test_italian_cf(self, detector):
        matches = detector.scan("CF: RSSMRA85M01H501Z")
        cf = [m for m in matches if m.pattern_name == "it_cf"]
        assert len(cf) == 1

    def test_indian_aadhaar(self, detector):
        matches = detector.scan("Aadhaar: 1234 5678 9012")
        aadhaar = [m for m in matches if m.pattern_name == "in_aadhaar"]
        assert len(aadhaar) == 1

    def test_iban(self, detector):
        matches = detector.scan("IBAN: DE89370400440532013000")
        iban = [m for m in matches if m.pattern_name == "iban"]
        assert len(iban) == 1

    def test_aws_key(self, detector):
        matches = detector.scan("AWS Key: AKIAIOSFODNN7EXAMPLE")
        aws = [m for m in matches if m.pattern_name == "aws_access_key"]
        assert len(aws) == 1

    def test_github_token(self, detector):
        matches = detector.scan("Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        gh = [m for m in matches if m.pattern_name == "github_token"]
        assert len(gh) == 1


class TestCreditCard:
    def test_visa(self, detector):
        matches = detector.scan("Card: 4111111111111111")
        cards = [m for m in matches if m.pattern_name == "credit_card"]
        assert len(cards) == 1

    def test_formatted_card(self, detector):
        matches = detector.scan("Card: 4111-1111-1111-1111")
        cards = [m for m in matches if m.pattern_name == "credit_card"]
        assert len(cards) >= 1


class TestAPIKeys:
    def test_openai_key(self, detector):
        key = "sk-" + "a" * 48
        matches = detector.scan(f"API Key: {key}")
        keys = [m for m in matches if "key" in m.pattern_name.lower()]
        assert len(keys) >= 1

    def test_anthropic_key(self, detector):
        # Fake key with same format (real keys blocked by GitHub secret scanning)
        key = "sk-ant-api03-" + "a" * 50 + "_" + "b" * 40 + "-test"
        matches = detector.scan(f"Key: {key}")
        keys = [m for m in matches if m.pattern_name == "anthropic_key"]
        assert len(keys) == 1
        assert matches[0].severity == "critical"


class TestRedaction:
    def test_redact_email(self, detector):
        text = "Contact user@example.com for help"
        redacted = detector.redact(text)
        assert "user@example.com" not in redacted
        assert "[EMAIL]" in redacted

    def test_redact_multiple(self, detector):
        text = "Email: test@test.com, Phone: +1-555-123-4567"
        redacted = detector.redact(text)
        assert "test@test.com" not in redacted


class TestHelpers:
    def test_has_pii(self, detector):
        assert detector.has_pii("user@example.com") is True
        assert detector.has_pii("Hello world") is False

    def test_get_pii_types(self, detector):
        text = "Email: test@test.com, Card: 4111111111111111"
        types = detector.get_pii_types(text)
        assert "email" in types
        assert "credit_card" in types


class TestAllowlist:
    """Tests for allowlist functionality."""

    def test_allowlist_exact_value(self):
        """Test allowing specific value."""
        detector = PIIDetector(allowlist=[
            {"type": "email", "value": "allowed@example.com"}
        ])

        # This email should be allowed (not detected)
        matches = detector.scan("Contact allowed@example.com for info")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 0

        # Other emails should still be detected
        matches = detector.scan("Contact other@example.com for info")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 1

    def test_allowlist_pattern(self):
        """Test allowing pattern (regex)."""
        detector = PIIDetector(allowlist=[
            {"type": "email", "pattern": r".*@company\.com"}
        ])

        # Emails matching pattern should be allowed
        matches = detector.scan("Contact john@company.com")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 0

        matches = detector.scan("Contact jane@company.com")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 0

        # Other domains should still be detected
        matches = detector.scan("Contact user@other.com")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 1

    def test_allowlist_type_only(self):
        """Test allowing all of a type."""
        detector = PIIDetector(allowlist=[
            {"type": "email"}  # Allow ALL emails
        ])

        # All emails should be allowed
        matches = detector.scan("Contact any@email.com and other@test.org")
        emails = [m for m in matches if m.pattern_name == "email"]
        assert len(emails) == 0

        # Other PII types should still be detected
        matches = detector.scan("SSN: 123-45-6789")
        ssns = [m for m in matches if m.pattern_name == "us_ssn"]
        assert len(ssns) == 1

    def test_allowlist_phone_value(self):
        """Test allowing specific phone number."""
        # Allow the full international format
        detector = PIIDetector(allowlist=[
            {"type": "phone", "value": "+5511999999999"},
            {"type": "phone", "pattern": r"5511999999\d*"},  # Also allow partial matches
        ])

        # This phone should be allowed (both full and partial matches)
        matches = detector.scan("Call +5511999999999")
        phones = [m for m in matches if "phone" in m.pattern_name]
        assert len(phones) == 0

        # Other phones should still be detected
        matches = detector.scan("Call +5511888888888")
        phones = [m for m in matches if "phone" in m.pattern_name]
        assert len(phones) >= 1

    def test_allowlist_multiple_rules(self):
        """Test multiple allowlist rules."""
        detector = PIIDetector(allowlist=[
            {"type": "email", "value": "safe@company.com"},
            {"type": "email", "pattern": r".*@internal\.corp"},
            {"type": "phone", "value": "+1234567890"},
        ])

        # Allowed email by value
        matches = detector.scan("Contact safe@company.com")
        assert len([m for m in matches if m.pattern_name == "email"]) == 0

        # Allowed email by pattern
        matches = detector.scan("Contact anyone@internal.corp")
        assert len([m for m in matches if m.pattern_name == "email"]) == 0

        # Not allowed email
        matches = detector.scan("Contact random@other.com")
        assert len([m for m in matches if m.pattern_name == "email"]) == 1

    def test_redact_respects_allowlist(self):
        """Test that redact() respects allowlist."""
        detector = PIIDetector(allowlist=[
            {"type": "email", "value": "allowed@example.com"}
        ])

        text = "Contact allowed@example.com or blocked@example.com"
        redacted = detector.redact(text)

        # Allowed email should NOT be redacted
        assert "allowed@example.com" in redacted
        # Blocked email should be redacted
        assert "blocked@example.com" not in redacted
        assert "[EMAIL]" in redacted
