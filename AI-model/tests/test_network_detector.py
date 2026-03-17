"""Tests for network / service exposure detection."""
import pytest
from pathlib import Path
from app.detectors.network_detector import scan_filesystem, scan_strings


def _make_fs(tmp_path: Path) -> Path:
    fs = tmp_path / "fs"
    fs.mkdir()
    etc = fs / "etc"
    etc.mkdir()
    return fs


def _ids(findings):
    return {f.finding_id for f in findings}


# ── filesystem scan ────────────────────────────────────────────────────────────

def test_telnet_in_inetd_conf(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "inetd.conf").write_text(
        "telnet stream tcp nowait root /usr/sbin/telnetd telnetd\n"
    )
    findings = scan_filesystem(fs)
    assert "NET_TELNET_ENABLED" in _ids(findings)


def test_ftp_in_init_script(tmp_path):
    fs = _make_fs(tmp_path)
    init_d = fs / "etc" / "init.d"
    init_d.mkdir()
    (init_d / "rcS").write_text("#!/bin/sh\nvsftpd &\n")
    findings = scan_filesystem(fs)
    assert "NET_FTP_ENABLED" in _ids(findings)


def test_dropbear_ssh(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "inittab").write_text("::respawn:/usr/sbin/dropbear -F\n")
    findings = scan_filesystem(fs)
    assert "NET_DROPBEAR_SSH" in _ids(findings)


def test_snmp_default_community(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "snmpd.conf").write_text("community public\nrocommunity private\n")
    findings = scan_filesystem(fs)
    assert "NET_SNMP_ENABLED" in _ids(findings)


def test_upnp_detected(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "inittab").write_text("::respawn:/usr/sbin/miniupnpd -f /etc/upnpd.conf\n")
    findings = scan_filesystem(fs)
    assert "NET_UPNP_ENABLED" in _ids(findings)


def test_no_findings_on_clean_fs(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "hostname").write_text("router\n")
    findings = scan_filesystem(fs)
    assert len(findings) == 0


def test_dedup_same_service_fires_once(tmp_path):
    fs = _make_fs(tmp_path)
    init_d = fs / "etc" / "init.d"
    init_d.mkdir()
    # telnetd mentioned in TWO files
    (fs / "etc" / "inetd.conf").write_text("telnet stream tcp nowait root telnetd\n")
    (init_d / "rcS").write_text("telnetd -l /bin/sh\n")
    findings = scan_filesystem(fs)
    telnet = [f for f in findings if f.finding_id == "NET_TELNET_ENABLED"]
    assert len(telnet) == 1


# ── strings scan (fallback when no FS) ────────────────────────────────────────

def test_scan_strings_detects_telnet():
    strings = ["start telnetd -l /bin/sh", "some other string"]
    findings = scan_strings(strings)
    assert "NET_TELNET_ENABLED" in _ids(findings)


def test_scan_strings_clean():
    findings = scan_strings(["hello", "world", "nginx config"])
    # nginx matches NET_HTTP_UNENCRYPTED
    assert "NET_HTTP_UNENCRYPTED" in _ids(findings)


def test_scan_strings_empty():
    assert scan_strings([]) == []
