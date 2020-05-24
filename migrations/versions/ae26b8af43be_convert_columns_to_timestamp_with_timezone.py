"""Convert columns to timestamp with timezone

Revision ID: ae26b8af43be
Revises: ef73879a2c3b
Create Date: 2020-05-24 17:34:37.591217

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'ae26b8af43be'
down_revision = 'ef73879a2c3b'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('state', 'when', type_=sa.DateTime(timezone=True), postgresql_using='"when" AT TIME ZONE \'UTC\'')
    op.alter_column('timer', 'schedule', type_=sa.DateTime(timezone=True), postgresql_using='schedule AT TIME ZONE \'UTC\'')


def downgrade():
    op.alter_column('state', 'when', type_=sa.DateTime())
    op.alter_column('timer', 'schedule', type_=sa.DateTime())
