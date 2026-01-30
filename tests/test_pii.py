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
        cpf = [m for m in matches if m.pattern_name == "cpf"]
        assert len(cpf) == 1
    
    def test_cpf_unformatted(self, detector):
        matches = detector.scan("CPF: 12345678900")
        cpf = [m for m in matches if m.pattern_name == "cpf"]
        assert len(cpf) == 1


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


class TestRedaction:
    def test_redact_email(self, detector):
        text = "Contact user@example.com for help"
        redacted = detector.redact(text)
        assert "user@example.com" not in redacted
        assert "[REDACTED]" in redacted
    
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
