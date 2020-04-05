"""Split thing status into separate types

Revision ID: c6eafb0dad45
Revises: d64d247238a7
Create Date: 2017-05-23 17:57:16.798977

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c6eafb0dad45'
down_revision = 'd64d247238a7'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('state', 'status', new_column_name='status_str')
    op.add_column('state', sa.Column('status_bool', sa.Boolean(), nullable=True))
    op.add_column('state', sa.Column('status_float', sa.Float(), nullable=True))


def downgrade():
    op.alter_column('state', 'status_str', new_column_name='status')
    op.drop_column('state', 'status_float')
    op.drop_column('state', 'status_bool')
