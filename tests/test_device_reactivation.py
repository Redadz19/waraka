from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine, select, func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main
from app.config import settings
from app.database import Base
from app.models import Device, EmailOTP, License
from app.schemas import ActivateRequest, DeactivateRequest
from app.security import hash_otp, hash_serial


def test_deactivated_device_can_be_reactivated(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    monkeypatch.setattr(settings, "otp_secret", "x" * 40)
    monkeypatch.setattr(main, "sign_payload", lambda payload: "test-signature")

    serial = "WRK-AAAA-BBBB-CCCC-DDDD"
    email = "buyer@example.com"
    device_id = "windows-device-123"
    now = datetime.now(timezone.utc)
    license_record = License(serial_hash=hash_serial(serial), email=email, expires_at=None)
    db.add(license_record)
    db.flush()

    def add_otp():
        db.add(EmailOTP(
            license_id=license_record.id,
            email=email,
            code_hash=hash_otp("123456"),
            expires_at=now + timedelta(minutes=10),
            created_at=now,
            attempts=0,
            consumed=False,
        ))
        db.commit()

    request = ActivateRequest(
        serial=serial,
        email=email,
        code="123456",
        device_id=device_id,
        device_name="Windows PC",
    )
    add_otp()
    main.activate(request, db)
    main.deactivate(DeactivateRequest(serial=serial, email=email, device_id=device_id), db)

    add_otp()
    result = main.activate(request, db)
    device = db.scalar(select(Device).where(Device.license_id == license_record.id, Device.device_id == device_id))

    assert result["license"]["expires_at"] is None
    assert device is not None and device.revoked is False
    assert db.scalar(select(func.count()).select_from(Device).where(Device.license_id == license_record.id)) == 1
    db.close()
    engine.dispose()
