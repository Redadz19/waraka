"""Initial WARAKA licensing schema."""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "licenses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("serial_hash", sa.String(64), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_licenses_serial_hash", "licenses", ["serial_hash"], unique=True)
    op.create_index("ix_licenses_email", "licenses", ["email"])
    op.create_table(
        "devices",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("license_id", sa.String(36), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(128), nullable=False),
        sa.Column("device_name", sa.String(200), nullable=False, server_default=""),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("license_id", "device_id", name="uq_license_device"),
    )
    op.create_index("ix_devices_license_id", "devices", ["license_id"])
    op.create_table(
        "email_otps",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("license_id", sa.String(36), sa.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("code_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("consumed", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_index("ix_email_otps_license_id", "email_otps", ["license_id"])
    op.create_index("ix_email_otps_email", "email_otps", ["email"])


def downgrade():
    op.drop_index("ix_email_otps_email", table_name="email_otps")
    op.drop_index("ix_email_otps_license_id", table_name="email_otps")
    op.drop_table("email_otps")
    op.drop_index("ix_devices_license_id", table_name="devices")
    op.drop_table("devices")
    op.drop_index("ix_licenses_email", table_name="licenses")
    op.drop_index("ix_licenses_serial_hash", table_name="licenses")
    op.drop_table("licenses")
