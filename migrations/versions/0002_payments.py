"""Add one-time purchase payment ledger."""

from alembic import op
import sqlalchemy as sa


revision = "0002_payments"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "payments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("provider_reference", sa.String(160), nullable=True),
        sa.Column("idempotency_key", sa.String(80), nullable=False),
        sa.Column("customer_email", sa.String(320), nullable=False),
        sa.Column("amount_minor", sa.Integer(), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("checkout_url", sa.String(2048), nullable=True),
        sa.Column("license_id", sa.String(36), sa.ForeignKey("licenses.id"), nullable=True),
        sa.Column("provider_metadata", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("provider", "provider_reference", name="uq_payment_provider_reference"),
        sa.UniqueConstraint("idempotency_key", name="uq_payments_idempotency_key"),
        sa.UniqueConstraint("license_id", name="uq_payment_license"),
        sa.CheckConstraint("amount_minor > 0", name="ck_payment_amount_positive"),
        sa.CheckConstraint(
            "status IN ('pending', 'paid', 'failed', 'refunded')",
            name="ck_payment_status",
        ),
    )
    op.create_index("ix_payments_customer_email", "payments", ["customer_email"])
    op.create_index("ix_payments_status", "payments", ["status"])


def downgrade():
    op.drop_index("ix_payments_status", table_name="payments")
    op.drop_index("ix_payments_customer_email", table_name="payments")
    op.drop_table("payments")
