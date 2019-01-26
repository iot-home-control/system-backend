import datetime
import timerqueue
import shared
from models.database import Timer
from pprint import pformat
import rules

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


def add_timer(timer_id, func, at=None, interval=None):
    if at and interval:
        raise RuntimeError("Time at and interval are not supported at the same time")
    func_name = func.__code__.co_name
    func_hash = str(fnv1a(func_name.encode()))
    logger.info("Adding function {} with hash {} to _functions table".format(func_name, func_hash))
    _functions[func_hash] = func
    db = shared.db_session_factory()
    timer = db.query(Timer).filter_by(id=timer_id).one_or_none()

    def set_timer_timing(timer, at, interval):
        if at:
            assert type(at) == datetime.datetime, "'at' must be datetime"
            timer.schedule = at
        elif interval:
            assert type(interval) == datetime.timedelta, "'at' must be timedelta"
            timer.schedule = datetime.datetime.utcnow() + interval
            timer.data["__interval__"] = interval.total_seconds()
        else:
            raise RuntimeError("Timer is neither at nor interval")

    if not timer:
        timer = Timer()
        timer.id = timer_id
        timer.function_id = func_hash
        timer.data = dict()
        set_timer_timing(timer, at, interval)
        db.add(timer)
        db.commit()
    else:
        timer.function_id = func_hash
        set_timer_timing(timer, at, interval)
        db.commit()
    db.close()


def process_timers():
    db = shared.db_session_factory()
    todo = db.query(Timer).filter(Timer.schedule < datetime.datetime.utcnow()).all()
    for timer in todo:
        if timer.function_id not in _functions:
            logger.warning("Timer '{}' has specifies function_id '{}' which is unknown".format(timer.id, timer.function_id))
            logger.warning("Known timers: {}".format(pformat(_functions)))
            continue
        _functions[timer.function_id](rules.RuleEvent(rules.EventSource.Timer, None, None))
        if "__interval__" in timer.data:
            timer.schedule += datetime.timedelta(seconds=timer.data["__interval__"])
        else:
            db.delete(timer)
        db.commit()

    db.close()
