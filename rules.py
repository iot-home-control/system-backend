from pprint import pprint
import models.database
import timer
import datetime
from enum import Enum


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
    Timer = 1
    Trigger = 2


def rule(name, *trigger, **params):
    def wrapper(func):
        def decorator(event, **kwargs):
            all_args = kwargs.copy()
            all_args.update(params)
            return func(event, **all_args)

        def init(db):
            for wrapper in trigger:
                for t in wrapper.resolve(db):
                    triggers.setdefault(t.id, []).append(decorator)
            all_rules[decorator] = name
        rule_inits.append(init)
        return decorator
    return wrapper


def init_timers():
    timer.add_timer("Test Timer", timer_test_rule, interval=datetime.timedelta(seconds=10))


@rule("Test", Thing("switch", name="Deckenlicht"))
def test_rule(event):
    thing, state = event.thing, event.state
    if state.event_source != "local":
        return
    if state.status_bool:
        thing.off()
    else:
        thing.on()


@rule("Timer_test")
def timer_test_rule(event):
    source, thing, state = event.source, event.thing, event.state
    print(source, thing, state)
