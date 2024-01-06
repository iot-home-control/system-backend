"""Rename LastSeen to DeviceInfo

Revision ID: b428fcb361e2
Revises: 6494eb528fb5
Create Date: 2024-01-05 16:55:00.903995

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b428fcb361e2'
down_revision = 'f913db1fc4d4'
branch_labels = None
depends_on = None


def upgrade():
    op.rename_table("last_seen", "device_information")


def downgrade():
    op.rename_table("device_information", "last_seen")
