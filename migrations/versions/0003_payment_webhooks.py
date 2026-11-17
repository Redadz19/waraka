"""Add Chargily webhook event ledger and license delivery recovery."""

from alembic import op
import sqlalchemy as sa


revision = "0003_payment_webhooks"
down_revision = "0002_payments"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "payments",
        "amount_minor",
        new_column_name="amount_dzd",
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
    op.add_column("payments", sa.Column("license_serial_ciphertext", sa.String(512), nullable=True))
    op.add_column("payments", sa.Column("license_email_sent_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "payments",
        sa.Column("license_email_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("payments", sa.Column("license_email_last_error", sa.String(200), nullable=True))
    op.create_table(
        "payment_webhook_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("event_id", sa.String(160), nullable=False),
        sa.Column("payment_id", sa.String(36), sa.ForeignKey("payments.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("provider", "event_id", name="uq_payment_webhook_provider_event"),
    )
    op.create_index("ix_payment_webhook_events_payment_id", "payment_webhook_events", ["payment_id"])


def downgrade():
    op.drop_index("ix_payment_webhook_events_payment_id", table_name="payment_webhook_events")
    op.drop_table("payment_webhook_events")
    op.drop_column("payments", "license_email_last_error")
    op.drop_column("payments", "license_email_attempts")
    op.drop_column("payments", "license_email_sent_at")
    op.drop_column("payments", "license_serial_ciphertext")
    op.alter_column(
        "payments",
        "amount_dzd",
        new_column_name="amount_minor",
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
