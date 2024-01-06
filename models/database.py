# SPDX-License-Identifier: AGPL-3.0-or-later
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import datetime
from enum import Enum
from typing import List, Optional

import sqlalchemy as sa
import sqlalchemy.orm
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.mutable import MutableDict

import config

Base = declarative_base()


class DataType(Enum):
    Nothing = 0
    Float = 1
    String = 2
    Boolean = 3


class DeviceInfo(Base):
    __tablename__ = "device_information"
    device_id = sa.Column(sa.String, primary_key=True)
    last_seen = sa.Column(sa.DateTime(timezone=True))
    ip_addr = sa.Column(sa.String, nullable=True)
    firmware_version = sa.Column(sa.String, nullable=True)
    is_updatable = sa.Column(sa.Boolean, nullable=True)
    data = sa.Column(sa.JSON(), nullable=False, default=dict)

    @classmethod
    def update_device_info(cls, db, device_id, threshold_s: Optional[int] = None, **infos):
        device_info = db.query(DeviceInfo).filter_by(device_id=device_id).one_or_none()
        if not device_info:
            device_info = DeviceInfo(device_id=device_id)
            db.add(device_info)
        now = datetime.datetime.now(tz=datetime.timezone.utc)

        # Add anything that shouldn't be updated by infos kwargs to this list.
        for reserved in ("device_id", "last_seen", "data"):
            infos.pop(reserved, None)

        infos_changed = False

        for key, value in infos.items():
            if hasattr(device_info, key):
                if getattr(device_info, key) != value:
                    infos_changed = True
                    setattr(device_info, key, value)
            else:
                if key not in device_info or device_info[key] != value:
                    infos_changed = True
                    device_info[key] = value
                    device_info.data.flag_modified()

        if any((infos_changed,
                device_info.last_seen is None,
                threshold_s is None,
                (threshold_s is not None and device_info.last_seen + datetime.timedelta(seconds=threshold_s) < now),
                )):
            device_info.last_seen = now
            db.commit()


thing_state_cache = dict()


class Thing(Base):
    __tablename__ = "thing"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String)
    type = sa.Column(sa.String)
    device_id = sa.Column(sa.String)
    vnode_id = sa.Column(sa.Integer, default=0)
    visible = sa.Column(sa.Boolean, default=True)
    last_seen = sa.orm.column_property(sa
                                       .select(DeviceInfo.last_seen)
                                       .where(DeviceInfo.device_id == device_id)
                                       .scalar_subquery())
    views = sa.orm.relationship("View", secondary="thing_view", lazy="dynamic", back_populates="things")
    ordering = sa.Column(sa.Integer)

    __mapper_args__ = {
        'polymorphic_on': type,
        'polymorphic_identity': 'thing'
    }

    def __repr__(self):
        return 'Thing(id={}, name="{}", type="{}", device_id="{}", vnode_id={}, visible={})'.format(self.id, self.name,
                                                                                                    self.type,
                                                                                                    self.device_id,
                                                                                                    self.vnode_id,
                                                                                                    self.visible)

    def last_state(self, db):
        if self.id not in thing_state_cache:
            state = db.query(State).filter_by(thing_id=self.id).order_by(State.when.desc()).first()
            if not state:
                state = db.query(Trend).filter_by(thing_id=self.id).order_by(Trend.end.desc()).first()
            thing_state_cache[self.id] = state

        return thing_state_cache[self.id]

    def get_state_topic(self):
        return "{type}/{device_id}/state".format(type=self.type, device_id=self.get_full_name())

    def get_action_topic(self):
        return "{type}/{device_id}/action".format(type=self.type, device_id=self.get_full_name())

    def get_full_name(self):
        return "{}-{}".format(self.device_id, self.vnode_id)

    def get_data_type(self):
        raise NotImplemented()

    def process_status(self, db, state, data):
        reason, value = state.split(",", maxsplit=1)

        state = State()
        state.thing_id = self.id
        state.when = datetime.datetime.now(tz=datetime.timezone.utc)
        state.event_source = reason
        data_type = self.get_data_type()
        if data_type == DataType.Float:
            state.status_float = float(value)
        elif data_type == DataType.Boolean:
            state.status_bool = value.lower() in ["on", "yes", "true", "1"]
        elif data_type == DataType.String:
            state.status_str = value
        elif data_type == DataType.Nothing:
            return self.id, type(self), "state", None
        else:
            raise RuntimeError("Unknown data type")

        db.add(state)
        db.commit()
        thing_state_cache[self.id] = state
        return self.id, type(self), "state", state.id

    @staticmethod
    def get_mqtt_subscriptions():
        return tuple()

    @staticmethod
    def get_by_type_and_device_id(db, node_type, device_id, vnode_id):
        from models.things import thing_type_table
        cls = thing_type_table.get(node_type)
        if not cls:
            raise ValueError()
        thing = db.query(cls).filter_by(type=node_type, device_id=device_id,
                                        vnode_id=vnode_id).one_or_none()
        return thing

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # type / node-vnode / state
        node_type = topic[0]
        device_id, vnode_id = topic[1].rsplit('-', maxsplit=1)
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None

    @staticmethod
    def get(db, thing_type, name=None, id=None, device_id=None, vnode_id=None):
        from models.things import thing_type_table
        cls = thing_type_table[thing_type]
        query = db.query(cls)
        if name:
            query = query.filter(Thing.name == name)
        if id:
            query = query.filter(Thing.id == id)
        if device_id:
            query = query.filter(Thing.device_id == device_id)
        if vnode_id:
            if not device_id:
                raise ValueError("vnode_id requires device_id")
            query = query.filter(Thing.vnode_id == vnode_id)
        things = query.all()
        return things

    def to_dict(self):
        return dict(id=self.id, name=self.name,
                    type=self.type, device_id=self.device_id,
                    vnode_id=self.vnode_id, visible=self.visible)

    @classmethod
    def display_name(cls):
        return "<undefined>"


class State(Base):
    __tablename__ = "state"
    __table_args__ = (sa.Index("ix_state_id_when", "id", "when"),)
    id = sa.Column(sa.Integer, primary_key=True)
    thing_id = sa.Column(sa.Integer, sa.ForeignKey('thing.id'))
    thing = sa.orm.relationship('Thing', backref=sa.orm.backref('states', lazy='dynamic'))
    when = sa.Column(sa.DateTime(timezone=True))
    event_source = sa.Column(sa.String)
    status_str = sa.Column(sa.String)
    status_bool = sa.Column(sa.Boolean)
    status_float = sa.Column(sa.Float)

    def to_dict(self):
        return dict(id=self.id, thing_id=self.thing_id, when=self.when,
                    event_source=self.event_source, status_str=self.status_str,
                    status_bool=self.status_bool, status_float=self.status_float)


class Timer(Base):
    __tablename__ = "timer"
    id = sa.Column(sa.String, primary_key=True)
    schedule = sa.Column(sa.DateTime(timezone=True), nullable=False)
    function_id = sa.Column(sa.String, nullable=False)
    data = sa.Column(MutableDict.as_mutable(sa.JSON), nullable=False, default=lambda: {})
    auto_delete = sa.Column(sa.Boolean)


class ThingView(Base):
    __tablename__ = "thing_view"
    thing_id = sa.Column(sa.Integer, sa.ForeignKey('thing.id'), primary_key=True)
    view_id = sa.Column(sa.Integer, sa.ForeignKey('view.id'), primary_key=True)


class View(Base):
    __tablename__ = "view"
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String, nullable=False)

    things = sa.orm.relationship("Thing", secondary="thing_view")


class RuleState(Base):
    __tablename__ = "rule_state"
    id = sa.Column(sa.String, primary_key=True)
    enabled = sa.Column(sa.Boolean, default=True)
    data = sa.Column(sa.JSON)


class Trend(Base):
    __tablename__ = 'trends'
    thing_id = sa.Column(sa.Integer, sa.ForeignKey('thing.id'), primary_key=True)
    # thing = sa.orm.relationship('Thing', backref=sa.orm.backref('states', lazy='dynamic'))

    interval = sa.Column(sa.types.Interval(native=True), nullable=False)
    start = sa.Column(sa.DateTime(timezone=True), primary_key=True)
    end = sa.Column(sa.DateTime(timezone=True))
    samples = sa.Column(sa.Integer, nullable=False)

    t_min = sa.Column(sa.Float)
    t_avg = sa.Column(sa.Float)
    t_max = sa.Column(sa.Float)

    def to_dict(self):
        when = self.start + (self.end - self.start) / 2
        return dict(thing_id=self.thing_id, when=when, status_str=None, status_bool=None, status_float=self.t_avg)


class User(Base):
    __tablename__ = 'users'
    id = sa.Column(sa.Integer, primary_key=True)
    name = sa.Column(sa.String, unique=True, nullable=False)
    pwhash = sa.Column(sa.String, nullable=False)
    display_name = sa.Column(sa.String)
