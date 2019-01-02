from shared import db_engine
import sqlalchemy as sa
from sqlalchemy.ext.declarative import declarative_base
from enum import Enum
import datetime

Base = declarative_base()


class DataType(Enum):
    Float = 1
    String = 2
    Boolean = 3


class LastSeen(Base):
    __tablename__ = "last_seen"
    device_id = sa.Column(sa.String, primary_key=True)
    last_seen = sa.Column(sa.DateTime)


class Thing(Base):
    __tablename__ = "thing"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String)
    type = sa.Column(sa.String)
    device_id = sa.Column(sa.String)
    vnode_id = sa.Column(sa.Integer, default=0)
    visible = sa.Column(sa.Boolean, default=True)

    def last_state(self):
        return State.query.filter_by(thing_id=self.id).order_by(State.when.desc()).first()

    def get_state_topic(self):
        return "/{type}/{device_id}/state".format(type=self.type, device_id=self.get_full_name())

    def get_action_topic(self):
        return "/{type}/{device_id}/action".format(type=self.type, device_id=self.get_full_name())

    def get_full_name(self):
        return "{}-{}".format(self.device_id, self.vnode_id)

    def get_data_type(self):
        raise NotImplemented()

    def process_status(self, db, state):
        reason, value = state.split(",", maxsplit=1)

        state = State()
        state.thing_id = self.id
        state.when = datetime.datetime.utcnow()
        state.event_source = reason
        data_type = self.get_data_type()
        if data_type == DataType.Float:
            state.status_float = float(value)
        elif data_type == DataType.Boolean:
            state.status_bool = value.lower() in ["on", "yes", "true", "1"]
        elif data_type == DataType.String:
            state.status_str = value
        else:
            raise RuntimeError("Unknown data type")

        db.add(state)
        db.commit()

    @staticmethod
    def get_by_type_and_device_id(db, node_type, device_id, vnode_id):
        from models.things import thing_type_table
        cls = thing_type_table.get(node_type)
        if not cls:
            raise ValueError()
        thing = db.query(cls).filter_by(type=node_type, device_id=device_id,
                                        vnode_id=vnode_id).one_or_none()
        return thing


class State(Base):
    __tablename__ = "state"
    id = sa.Column(sa.Integer, primary_key=True)
    thing_id = sa.Column(sa.Integer, sa.ForeignKey('thing.id'))
    thing = sa.orm.relationship('Thing', backref=sa.orm.backref('states', lazy='dynamic'))
    when = sa.Column(sa.DateTime)
    event_source = sa.Column(sa.String)
    status_str = sa.Column(sa.String)
    status_bool = sa.Column(sa.Boolean)
    status_float = sa.Column(sa.Float)
