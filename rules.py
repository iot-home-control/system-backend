from pprint import pprint
from models.database import Thing
from __main__ import db_session as db

all_rules = {}
triggers = {}


def thing(thing_type, name=None, id=None, device_id=None, vnode_id=None):
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


def rule(name, trigger, **params):
    def wrapper(func):
        def decorator(*args, **kwargs):
            all_args = kwargs.copy()
            all_args.update(params)
            return func(*args, **all_args)

        for t in trigger if type(trigger) == list else [trigger]:
            triggers.setdefault(t, []).append(decorator)
        all_rules[decorator] = name
        return decorator
    return wrapper


@rule("Test", thing("switch", name="\"Stern\""), a=1, b=2)
def test_rule(a, b, **kwargs):
    print(a, b, kwargs)


