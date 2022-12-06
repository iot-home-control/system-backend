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
import logging
from pprint import pformat

import croniter
import dateutil.tz

import config
import rules
import shared
from models.database import Timer

tz = dateutil.tz.gettz(getattr(config, "TIMEZONE", "UTC"))


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


def timer(func):
    func_name = func.__name__
    func_hash = str(fnv1a(func_name.encode()))
    _functions[func_hash] = func
    return func


def add_timer(timer_id, func, at=None, interval=None, cron=None, auto_delete=None):
    if at and interval and cron:
        raise RuntimeError("Time at, interval and cron are not supported at the same time")
    func_name = func.__name__
    func_hash = str(fnv1a(func_name.encode()))
    assert func_hash in _functions, f"{func_name} must be a registered timer function " \
                                    f"(have the @timer decorator) in order to be used with add_timer"

    def set_timer_timing(timer):
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

    """Default behaviour of auto_delete
    at: auto_delete=False i.e. they will be executed after a reboot
    cron: auto_delete=True
    interval: auto_delete=True
    Nonetheless, the default behaviour can be overwritten be setting auto_delete explicitly
    """
    def set_auto_delete(timer):
        if auto_delete is not None:
            timer.auto_delete = auto_delete
        elif at:
            timer.auto_delete = False
        else:
            timer.auto_delete = True

    with shared.db_session_factory() as db:
        timer = db.query(Timer).filter_by(id=timer_id).one_or_none()

        if not timer:
            timer = Timer()
            timer.id = timer_id
            timer.data = dict()
            db.add(timer)

        timer.function_id = func_hash
        set_auto_delete(timer)
        set_timer_timing(timer)
        db.commit()


def process_timers():
    with shared.db_session_factory() as db:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        now_tz = datetime.datetime.now(tz=tz)
        todo = db.query(Timer).filter(Timer.schedule < now).all()
        for timer in todo:
            if timer.function_id not in _functions:
                logger.warning(f"Timer '{timer.id}' has specifies function_id '{timer.function_id}' which is unknown")
                logger.warning("Known timers: {}".format(pformat(_functions)))
                continue
            timer_res = _functions[timer.function_id](rules.RuleEvent(rules.EventSource.Timer, None, None))
            if isinstance(timer, str) and timer_res == "DELETE":
                db.delete(timer)
            elif "__cron__" in timer.data:
                timer.schedule = croniter.croniter(timer.data["__cron__"], now_tz).get_next(ret_type=datetime.datetime)
                logger.info("Scheduled timer '{}' next at at {}".format(timer.id, timer.schedule))
            elif "__interval__" in timer.data:
                timer.schedule += datetime.timedelta(seconds=timer.data["__interval__"])
            else:
                db.delete(timer)
            db.commit()
