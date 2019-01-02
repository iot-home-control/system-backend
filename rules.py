from pprint import pprint
import models.database

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
    def __init__(self, thing, state):
        self.thing = thing
        self.state = state


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


@rule("Test", Thing("switch", name="Deckenlicht"))
def test_rule(event):
    thing, state = event.thing, event.state
    if state.event_source != "local":
        return
    if state.status_bool:
        thing.off()
    else:
        thing.on()


