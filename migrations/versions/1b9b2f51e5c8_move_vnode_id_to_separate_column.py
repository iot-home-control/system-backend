"""move vnode_id to separate column

Revision ID: 1b9b2f51e5c8
Revises: c6eafb0dad45
Create Date: 2017-06-11 17:55:10.549849

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker
from models.database import Thing
Session = sessionmaker()

# revision identifiers, used by Alembic.
revision = '1b9b2f51e5c8'
down_revision = 'c6eafb0dad45'
branch_labels = None
depends_on = None
Session = sessionmaker()

def upgrade():
    op.add_column('thing', sa.Column('vnode_id', sa.Integer(), nullable=True))
    bind = op.get_bind()
    session = Session(bind=bind)
    for thing in session.query(Thing):
        device_id = thing.device_id
        print(device_id)
        parts = device_id.split("-")
        try:
            thing.vnode_id = int(parts[-1])
            thing.device_id = "-".join(parts[:-1])
        except ValueError:
            thing.vnode_id = 0
            thing.device_id = device_id
    session.commit()


def downgrade():
    bind = op.get_bind()
    session = Session(bind=bind)
    for thing in Thing.query.all():
        thing.device_id = "{}-{}".format(thing.device_id, thing.vnode_id)
    session.commit()
    op.drop_column('thing', 'vnode_id')
