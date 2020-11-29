"""Add rule_state table

Revision ID: 661f15cfb036
Revises: ae26b8af43be
Create Date: 2020-11-29 17:39:32.768774

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '661f15cfb036'
down_revision = 'ae26b8af43be'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('rule_state',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('rule_state')
    # ### end Alembic commands ###
