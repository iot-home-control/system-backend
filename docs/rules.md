
# Writing rules
You can write your own rules by creating a `local_rules.py` file in the installation directory.
There are examples in `local_rules.py.example` which is also in the installation directory.

We have rules and timers.
Rules are functions which are called when either
- a timer expires (see later),
- a thing specified as rule trigger changes state
- another event happens, such as button presses or scene changes.

A rule is a function with the `@rule` decorator applied. The rule decorator take a rule identifier as the first argument. Please note that rule identifiers must be unique.
The decorator also takes any number of `Thing` descriptor objects as positional arguments after the identifier. All keyword arguments are also passed to the called function.
Please also note that the `Thing` descriptor object for rules is different from the `Thing` objects that are stored in the database, they must be resolved first into the latter.

Timers are function which are called based on a schedule. A function becomes a timer when it has the `@timer` decorator applied and is passed as the function argument to the `timer.add_timer` function.
You must also pass a unique timer id as the first argument.
There are three types of schedules:
- Cron (following a set schedule)
- Absolute (`at` argument, the function is called at a specific timestamp)
- Relative (`interval` argument the function is called after the specified time has elapsed, repeatedly if wanted)

Timers can delete themselves by returning the string "DELETE".
Each timer can only have one of the modes active at the same time (`at`, `interval`, and `cron` keyword arguments).
Timers are stored in the database.
After a restart timers with `interval` and `cron` keyword arguments are deleted to prevent from getting stale if their registrations (`add_timer` calls) have been deleted from source code.
You can prevent automatic deletion of `interval` and `cron` timers by explicitly setting the `auto_delete` keyword argument to `True` when calling `add_timer`.
Timers with `at` will be kept after a restart as they default to `False` for the `auto_delete` keyword argument.

Timers with `at` schedule will be executed at the scheduled time or later, when the system backend is restarted, if it was not running at the originally scheduled time unless `auto_delete` was set to `True` in `add_timer`.

The timer module has the function `is_scheduled(timer_id)` which can be called in `local_rules.py`.
The function returns `True` if there is a timer in database with given `timer_id` and its `schedule` is in the future, otherwise it returns `False`.

## Examples

**Switch on a lamp with a detached switch.**
We have the following things:
- the lamp:
  * name: "My Lamp"
  * type: "shelly"
- the switch
  * name: "My Switch"
  * type: "switch"

We want to switch on "My Lamp" based on the state off "My Switch".

```python
import shared
from rules import Thing, rule, RuleEvent
@rule("rule_switch_lamp_on_switch_event", Thing("switch", name="My Switch"))
def switch_lamp_on_switch(event: RuleEvent):
    with shared.db_session_factory() as db:
        my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
        if event.state.status_bool:
           my_lamp.on()
        else:
            my_lamp.off()
```

Wouldn't it be nice, if the "My Lamp" switches automatically off, when we go to bed.
Let's use a cron based timer for it.

First, we need a function which switches off "My Lamp". 

```python
import timer
@timer.timer
@rule("timer_switch_off_my_lamp")
def switch_off_my_lamp(event):
    with shared.db_session_factory() as db:
        my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
        my_lamp.off()
```

Then, we have to define a timer, which switches off "My Lamp" at 22:30 from Mon to Fri.
The timer is added with `timer.add_timer()`.
We put this function call in a function named `init_timers()`.
This ensures that the timer will be called by system backend.
To make sure we can add it as the timer function in the next step we'll also need to add the `@timer.timer` decorator to the function as well.

```python
def init_timers():
    timer.add_timer("good night", switch_off_my_lamp, cron="30 22 * * Mon-Fri")
```

Unfortunately, the light now switched off before we got to bed.
It would be nice if we could switch "My Lamp" on again, till we got really to bed.
Therefore, we need another device.
A "shelly button1" could be a good choice her, since it just sends only an event and has no state.

- the "shelly button1"
  * name: "Timed light switch"
  * type: "shellybutton"
  * device_id="shellybutton1-DEVICE_ID"

```python
import datetime
import config
import dateutil

tz = dateutil.tz.gettz(getattr(config, "TIMEZONE", "UTC"))
@rule("rule_keep_the_lights_on", Thing("shellybutton", device_id="shellybutton1-DEVICE_ID"))
def button_rule(event):
    with shared.db_session_factory() as db:
        my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
        if event.state == "S":
            my_lamp.on()
            timer.add_timer("timer_switch_off_my_lamp", switch_off_my_lamp, at=datetime.datetime.now(tz)+datetime.timedelta(minutes=5))
```