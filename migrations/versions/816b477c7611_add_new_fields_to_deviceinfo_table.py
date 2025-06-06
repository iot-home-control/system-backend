"""Add new fields to DeviceInfo table

Revision ID: 816b477c7611
Revises: b428fcb361e2
Create Date: 2024-01-05 17:10:18.481332

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '816b477c7611'
down_revision = 'b428fcb361e2'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('device_information', sa.Column('ip_addr', sa.String(), nullable=True))
    op.add_column('device_information', sa.Column('firmware_version', sa.String(), nullable=True))
    op.add_column('device_information', sa.Column('is_updatable', sa.Boolean(), nullable=True))
    op.add_column('device_information', sa.Column('data', sa.JSON(), nullable=True))

    op.execute("UPDATE device_information SET data ='{}'")

    op.alter_column('device_information', 'data', nullable=False)


def downgrade():
    op.drop_column('device_information', 'data')
    op.drop_column('device_information', 'is_updatable')
    op.drop_column('device_information', 'firmware_version')
    op.drop_column('device_information', 'ip_addr')
