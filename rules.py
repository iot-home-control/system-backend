# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2021 The Home Control Authors
#
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

import models.database
from enum import Enum
import functools

all_rules = {}
triggers = {}
rule_inits = []


def init(db):
    for func in rule_inits:
        func(db)


class Thing:
    def __init__(self, thing_type, name=None, id=None, device_id=None, vnode_id=None):
        self.thing_type = thing_type
        self.name = name
        self.id = id
        self.device_id = device_id
        self.vnode_id = vnode_id

    def resolve(self, db):
        return models.database.Thing.get(db, self.thing_type, self.name, self.id, self.device_id, self.vnode_id)


class RuleEvent:
    def __init__(self, source, thing, state):
        self.source = source
        self.thing = thing
        self.state = state


class EventSource(Enum):
    Timer = 1  # when a timer timed out
    Trigger = 2  # when status of a thing has changed
    Event = 3  # when something else happened (e.g. scene button in web interface, shelly button)


def rule(name, *trigger, **params):
    def wrapper(func):
        @functools.wraps(func)
        def decorator(event, **kwargs):
            all_args = kwargs.copy()
            all_args.update(params)
            return func(event, **all_args)

        def init_func(db):
            for thing_wrapper in trigger:
                for thing in thing_wrapper.resolve(db):
                    triggers.setdefault(thing.id, []).append(decorator)
            all_rules[decorator] = name

        rule_inits.append(init_func)
        return decorator

    return wrapper


def init_timers():
    pass
