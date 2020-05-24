"""Add index to State table

Revision ID: ef73879a2c3b
Revises: dd00c26615e7
Create Date: 2020-05-21 18:04:32.936358

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ef73879a2c3b'
down_revision = 'dd00c26615e7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_state_id_when', 'state', ['id', 'when'], unique=False)


def downgrade():
    op.drop_index('ix_state_id_when', table_name='state')
