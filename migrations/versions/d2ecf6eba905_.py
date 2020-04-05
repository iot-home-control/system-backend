"""empty message

Revision ID: d2ecf6eba905
Revises: 42eae3f77164
Create Date: 2017-11-12 15:07:17.283556

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd2ecf6eba905'
down_revision = '42eae3f77164'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('thing', sa.Column('visible', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('thing', 'visible')
    # ### end Alembic commands ###
