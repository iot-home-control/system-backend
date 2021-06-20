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

import datetime
import croniter

import shared
from models.database import Timer
from pprint import pformat
import rules

import config
import dateutil
tz = dateutil.tz.gettz(getattr(config, "TIMEZONE", "UTC"))

import logging
logger = logging.getLogger("timer")

_functions = {}


def fnv1a(xs):
    if type(xs) == str:
        xs = xs.encode()
    h = 0xcbf29ce484222325
    for x in xs:
        h = h ^ x
        h = (h * 0x100000001b3) & 2**64-1
    return h


def add_timer(timer_id, func, at=None, interval=None, cron=None):
    if at and interval and cron:
        raise RuntimeError("Time at, interval and cron are not supported at the same time")
    func_name = func.__code__.co_name
    func_hash = str(fnv1a(func_name.encode()))
    _functions[func_hash] = func
    db = shared.db_session_factory()
    timer = db.query(Timer).filter_by(id=timer_id).one_or_none()

    def set_timer_timing(timer, at, interval, cron):
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        nowtz = datetime.datetime.now(tz=tz)
        if at:
            assert type(at) == datetime.datetime, "'at' must be datetime"
            timer.schedule = at
        elif cron:
            assert type(cron) == str, "'cron' must be string"
            timer.schedule = croniter.croniter(cron, nowtz).get_next(ret_type=datetime.datetime)
            timer.data["__cron__"] = cron
        elif interval:
            assert type(interval) == datetime.timedelta, "'at' must be timedelta"
            timer.schedule = now + interval
            timer.data["__interval__"] = interval.total_seconds()
        else:
            raise RuntimeError("Timer is neither at, interval nor cron")

    if not timer:
        timer = Timer()
        timer.id = timer_id
        timer.function_id = func_hash
        timer.data = dict()
        set_timer_timing(timer, at, interval, cron)
        db.add(timer)
        db.commit()
    else:
        timer.function_id = func_hash
        set_timer_timing(timer, at, interval, cron)
        db.commit()
    db.close()


def process_timers():
    db = shared.db_session_factory()
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    nowtz = datetime.datetime.now(tz=tz)
    todo = db.query(Timer).filter(Timer.schedule < now).all()
    for timer in todo:
        if timer.function_id not in _functions:
            logger.warning("Timer '{}' has specifies function_id '{}' which is unknown".format(timer.id, timer.function_id))
            logger.warning("Known timers: {}".format(pformat(_functions)))
            continue
        timer_res = _functions[timer.function_id](rules.RuleEvent(rules.EventSource.Timer, None, None))
        if isinstance(timer, str) and timer_res == "DELETE":
            db.delete(timer)
        elif "__cron__" in timer.data:
            timer.schedule = croniter.croniter(timer.data["__cron__"], nowtz).get_next(ret_type=datetime.datetime)
            logger.info("Scheduled timer '{}' next at at {}".format(timer.id, timer.schedule))
        elif "__interval__" in timer.data:
            timer.schedule += datetime.timedelta(seconds=timer.data["__interval__"])
        else:
            db.delete(timer)
        db.commit()

    db.close()
