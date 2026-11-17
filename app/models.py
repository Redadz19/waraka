import uuid
from datetime import datetime, timezone
from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class License(Base):
    __tablename__ = "licenses"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    serial_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    devices: Mapped[list["Device"]] = relationship(back_populates="license", cascade="all, delete-orphan")
    otp_codes: Mapped[list["EmailOTP"]] = relationship(back_populates="license", cascade="all, delete-orphan")


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (UniqueConstraint("license_id", "device_id", name="uq_license_device"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id: Mapped[str] = mapped_column(ForeignKey("licenses.id", ondelete="CASCADE"), index=True)
    device_id: Mapped[str] = mapped_column(String(128))
    device_name: Mapped[str] = mapped_column(String(200), default="")
    activated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    license: Mapped["License"] = relationship(back_populates="devices")


class EmailOTP(Base):
    __tablename__ = "email_otps"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    license_id: Mapped[str] = mapped_column(ForeignKey("licenses.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    consumed: Mapped[bool] = mapped_column(Boolean, default=False)
    license: Mapped["License"] = relationship(back_populates="otp_codes")



class Payment(Base):
    """One-off purchase ledger; a paid transaction can issue at most one license."""
    __tablename__ = "payments"
    __table_args__ = (
        UniqueConstraint("provider", "provider_reference", name="uq_payment_provider_reference"),
        UniqueConstraint("idempotency_key", name="uq_payments_idempotency_key"),
        UniqueConstraint("license_id", name="uq_payment_license"),
        CheckConstraint("amount_dzd > 0", name="ck_payment_amount_positive"),
        CheckConstraint(
            "status IN ('pending', 'paid', 'failed', 'refunded')",
            name="ck_payment_status",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    provider_reference: Mapped[str | None] = mapped_column(String(160), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(80), nullable=False)
    customer_email: Mapped[str] = mapped_column(String(320), index=True)
    amount_dzd: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False, index=True)
    checkout_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    license_id: Mapped[str | None] = mapped_column(ForeignKey("licenses.id"), nullable=True)
    provider_metadata: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    license_serial_ciphertext: Mapped[str | None] = mapped_column(String(512), nullable=True)
    license_email_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    license_email_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    license_email_last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)



class PaymentWebhookEvent(Base):
    __tablename__ = "payment_webhook_events"
    __table_args__ = (
        UniqueConstraint("provider", "event_id", name="uq_payment_webhook_provider_event"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    event_id: Mapped[str] = mapped_column(String(160), nullable=False)
    payment_id: Mapped[str] = mapped_column(ForeignKey("payments.id", ondelete="CASCADE"), index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
