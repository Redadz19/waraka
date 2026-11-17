from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.config import settings
from app.main import build_activation_payload


def test_lifetime_license_payload_has_no_expiry(monkeypatch):
    monkeypatch.setattr(settings, "offline_grace_days", 14)
    monkeypatch.setattr(settings, "recheck_days", 7)
    now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
    license_record = SimpleNamespace(id="license-1", expires_at=None)
    device = SimpleNamespace(device_id="device-12345678")

    payload = build_activation_payload(license_record, device, "buyer@example.com", now)

    assert payload["expires_at"] is None
    assert payload["offline_grace_days"] == 14
    assert payload["recheck_days"] == 7
    assert payload["license_id"] == "license-1"
    assert payload["device_id"] == "device-12345678"


def test_expiring_license_payload_contains_utc_expiry():
    now = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
    expiry = now + timedelta(days=365)
    license_record = SimpleNamespace(id="license-2", expires_at=expiry)
    device = SimpleNamespace(device_id="device-87654321")

    payload = build_activation_payload(license_record, device, "buyer@example.com", now)

    assert payload["expires_at"] == expiry.isoformat()
