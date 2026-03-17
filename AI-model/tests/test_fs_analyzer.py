"""Tests for embedded filesystem / configuration analysis."""
import pytest
from pathlib import Path
from app.detectors.fs_analyzer import scan_filesystem


def _make_fs(tmp_path: Path) -> Path:
    fs = tmp_path / "fs"
    fs.mkdir()
    (fs / "etc").mkdir()
    return fs


def _ids(findings):
    return {f.finding_id for f in findings}


# ── /etc/passwd ────────────────────────────────────────────────────────────────

def test_passwd_empty_password(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "passwd").write_text(
        "root::0:0:root:/root:/bin/sh\n"   # empty password field
        "user:x:1000:1000::/home/user:/bin/sh\n"
    )
    findings = scan_filesystem(fs)
    assert "FS_PASSWD_EMPTY" in _ids(findings)
    f = next(f for f in findings if f.finding_id == "FS_PASSWD_EMPTY")
    assert f.severity == "critical"
    assert "CWE-798" in f.cwe


def test_passwd_root_shell(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/bin/sh\n"
    )
    findings = scan_filesystem(fs)
    assert "FS_ROOT_SHELL" in _ids(findings)


def test_passwd_clean(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "passwd").write_text(
        "root:x:0:0:root:/root:/sbin/nologin\n"
        "daemon:x:1:1::/:/sbin/nologin\n"
    )
    findings = scan_filesystem(fs)
    pw_ids = {"FS_PASSWD_EMPTY", "FS_ROOT_SHELL"}
    assert not pw_ids.intersection(_ids(findings))


# ── /etc/shadow ────────────────────────────────────────────────────────────────

def test_shadow_md5_hash(tmp_path):
    fs = _make_fs(tmp_path)
    # $1$ prefix = MD5 crypt
    (fs / "etc" / "shadow").write_text(
        "root:$1$salt$hashedpassword:18000:0:99999:7:::\n"
    )
    findings = scan_filesystem(fs)
    assert "FS_SHADOW_WEAK_HASH" in _ids(findings)
    f = next(f for f in findings if f.finding_id == "FS_SHADOW_WEAK_HASH")
    assert "CWE-916" in f.cwe


# ── WiFi PSK ───────────────────────────────────────────────────────────────────

def test_wifi_psk_in_wpa_supplicant(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "wpa_supplicant.conf").write_text(
        'network={\n  ssid="HomeNetwork"\n  psk="mysecretwifi"\n}\n'
    )
    findings = scan_filesystem(fs)
    assert "FS_WIFI_PSK_HARDCODED" in _ids(findings)
    f = next(f for f in findings if f.finding_id == "FS_WIFI_PSK_HARDCODED")
    assert "CWE-798" in f.cwe


# ── Private key ────────────────────────────────────────────────────────────────

def test_private_key_in_etc(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
    )
    findings = scan_filesystem(fs)
    assert "FS_PRIVATE_KEY_EMBEDDED" in _ids(findings)
    f = next(f for f in findings if f.finding_id == "FS_PRIVATE_KEY_EMBEDDED")
    assert f.severity == "critical"
    assert "CWE-321" in f.cwe


# ── Default credentials ────────────────────────────────────────────────────────

def test_default_creds_in_config(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "app.conf").write_text('admin_password=admin\n')
    findings = scan_filesystem(fs)
    assert "FS_DEFAULT_CREDENTIALS" in _ids(findings)


# ── World-writable ─────────────────────────────────────────────────────────────

def test_world_writable_config(tmp_path):
    fs = _make_fs(tmp_path)
    cfg = fs / "etc" / "sensitive.conf"
    cfg.write_text("secret=value\n")
    cfg.chmod(0o666)   # world-writable
    findings = scan_filesystem(fs)
    assert "FS_WORLD_WRITABLE_CONFIG" in _ids(findings)
    f = next(f for f in findings if f.finding_id == "FS_WORLD_WRITABLE_CONFIG")
    assert "CWE-732" in f.cwe


def test_clean_filesystem(tmp_path):
    fs = _make_fs(tmp_path)
    (fs / "etc" / "hostname").write_text("mydevice\n")
    findings = scan_filesystem(fs)
    assert len(findings) == 0
