import pytest

from app.config import settings
from app.security import hash_otp, hash_serial, hash_value, new_serial


def test_hash_is_stable():
    assert hash_value("WARAKA") == hash_value("WARAKA")
    assert hash_value("WARAKA") != hash_value("waraka")


def test_serial_hash_is_case_and_whitespace_insensitive():
    serial = "WRK-ABCD-1234-EF56-7890"
    assert hash_serial(serial) == hash_serial(f"  {serial.lower()}  ")


def test_serial_format_and_uniqueness():
    first, second = new_serial(), new_serial()
    parts = first.split("-")
    assert parts[0] == "WRK"
    assert len(parts) == 9
    assert all(len(part) == 4 for part in parts[1:])
    assert first != second


def test_otp_hash_requires_server_secret(monkeypatch):
    monkeypatch.setattr(settings, "otp_secret", "")
    with pytest.raises(RuntimeError):
        hash_otp("123456")


def test_otp_hash_uses_secret_and_is_stable(monkeypatch):
    monkeypatch.setattr(settings, "otp_secret", "x" * 40)
    first = hash_otp("123456")
    assert first == hash_otp("123456")
    assert first != hash_otp("654321")
    monkeypatch.setattr(settings, "otp_secret", "y" * 40)
    assert first != hash_otp("123456")
