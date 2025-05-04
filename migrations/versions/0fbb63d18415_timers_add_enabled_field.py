"""timers: add enabled field

Revision ID: 0fbb63d18415
Revises: 816b477c7611
Create Date: 2025-02-03 11:56:29.585016

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0fbb63d18415'
down_revision = '816b477c7611'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('timer', sa.Column('enabled', sa.Boolean()))
    op.execute("UPDATE timer SET enabled='t';")
    op.alter_column('timer', 'enabled', nullable=False)


def downgrade():
    op.drop_column('timer', 'enabled')

