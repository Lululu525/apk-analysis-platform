"""Tests for rule-based detector — verifies CWE/CVE fields are populated."""
import pytest
from app.detectors.rules import scan_text_for_rules


def _ids(findings):
    return {f.finding_id for f in findings}


def _by_id(findings, fid):
    return next((f for f in findings if f.finding_id == fid), None)


# ── individual rule triggers ───────────────────────────────────────────────────

def test_hardcoded_password():
    findings = scan_text_for_rules('password="supersecret123"')
    assert "HARDCODED_PASSWORD" in _ids(findings)
    f = _by_id(findings, "HARDCODED_PASSWORD")
    assert "CWE-798" in f.cwe
    assert f.severity == "high"


def test_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    findings = scan_text_for_rules(text)
    f = _by_id(findings, "PRIVATE_KEY_PEM")
    assert f is not None
    assert f.severity == "critical"
    assert "CWE-321" in f.cwe
    assert len(f.cve_examples) > 0


def test_aws_key():
    findings = scan_text_for_rules("AKIAIOSFODNN7EXAMPLE")
    f = _by_id(findings, "AWS_ACCESS_KEY")
    assert f is not None
    assert f.severity == "critical"


def test_telnet_enabled():
    findings = scan_text_for_rules("start telnetd -l /bin/sh")
    f = _by_id(findings, "TELNET_ENABLED")
    assert f is not None
    assert "CWE-319" in f.cwe


def test_gets_function():
    findings = scan_text_for_rules("gets(buf);")
    f = _by_id(findings, "GETS_FUNCTION")
    assert f is not None
    assert "CWE-120" in f.cwe


def test_weak_hash_md5():
    findings = scan_text_for_rules("MD5(input, len, digest);")
    f = _by_id(findings, "WEAK_HASH_MD5")
    assert f is not None
    assert "CWE-328" in f.cwe


def test_no_false_positive_clean_text():
    findings = scan_text_for_rules("Hello, world! This is a normal string.")
    assert len(findings) == 0


def test_dedup_same_rule_fires_once():
    # Two password patterns in same text → one finding
    text = 'password="abc"\npassword="def"'
    findings = scan_text_for_rules(text)
    pw_findings = [f for f in findings if f.finding_id == "HARDCODED_PASSWORD"]
    assert len(pw_findings) == 1


def test_multiple_rules_independent():
    text = 'password="x"\ntelnetd running\ngets(buf)'
    findings = scan_text_for_rules(text)
    ids = _ids(findings)
    assert "HARDCODED_PASSWORD" in ids
    assert "TELNET_ENABLED" in ids
    assert "GETS_FUNCTION" in ids
