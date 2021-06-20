# Home Control

Home Control is a no-cloud Internet of Things solution. 

Home Control has 3 Components
- the System Backend (this repository)
- the [Web Frontend](../frontend/README.md)
- the firmware (to be released)

The System Backend connects to a Message Queue (MQTT) to get state messages of things (the T in IoT).
A received state is saved to a database and sent to all active web frontends via a web socket connection.
The Backend provides also a Grafana data source.
The system backend can collate the collected data into trends.

The System Backend has support for rules and timers written in Python.

## Installation Guide
### Requirements
Home Control is a Python project and as such should be able to run on most platforms supported by Python 3.
On your system you should install (or should have available on your network):
- Python3 (at least Python 3.7)
- Python-Virtualenv (python3-venv)
- PostgreSQL.  
  MySQL might also work (you need to install a database driver manually. 
  See [SQLAlchemy documentation](https://docs.sqlalchemy.org/en/12/orm/tutorial.html#connecting).
  However, we have not tested it.)
- A MQTT message queue e.g., mosquitto
- A webserver, which can handle websockets (we recommend nginx)

Optionally, you can also install:
- grafana

### Setup
In the following we assume all non-absolute paths will be relative to the installation directory.
In all our example configuration files we assume `/opt/home-control/system-backend` to be the installation location.

1. Unpack the downloaded release file (or clone this repository)  to the installation directory.
1. Create a Python virtual environment in the installation directory (it will be in a folder named venv)  
   `python3 -m venv venv`.
1. *Optional:* Activate the virtualenv by running `. venv/bin/activate`.
   If you do this you can leave out the `./venv/bin/` in future commands.
   The virtualenv can be deactivated with `deactivate` after you're done.   
1. Install the required packages into the virtualenv  
   `./venv/bin/pip install -r requirements.txt`.
1. Create an empty database (and a database user) for Home Control.
   How to do that depends on your database server.
1. Create a config file for Home Control (you can copy `config.example.py` to `config.py` for a quick start) and fill it out.
   See [the configuration section](#Configuration) for more information.
1. Initialize the database by running  
   `./venv/bin/alembic upgrade head`.
1. We recommend configuring your webserver to forward WebSocket connections to the location `/ws` to Home Control.
   We provide a nginx configuration snippet for this in `examples/`.
   To configure Home Control via the web interface you'll also need a working TLS setup so this is a good point to also configure your web server for it.
1. Create one or more users. Users are necessary to add and configure things via the web interface.
   `./venv/bin/python main.py add-user <USERNAME>`. While running the command will ask you for the user's password.
1. Start Home Control by either:
    - running `./venv/bin/python main.py run` in your terminal.
    - installing and enabling the systemd unit file included in the `examples/` directory.
1. *Optional:* Set up automatic database housekeeping.
   It is used to aggregate data after a while and provide long term trends for your data.
   Configure your system to run `./venv/bin/python main.py database-housekeeping` regularly, for example 4 times a day, by setting up a cronjob or installing the provided systemd timer unit in `examples/`.

### Configuration
The configuration file is a text file consisting of multiple lines. Lines starting with `#` are comments and will be ignored.

- `SQLALCHEMY_DATABASE_URI = "driver://user:password@host/db"`
  defines the connection your database.
  See the [SQLAlchemy documentation](https://docs.sqlalchemy.org/en/12/orm/tutorial.html#connecting) for information on what to use for your setup.
  For PostgreSQL, with a database named `home-control` and Home Control running as the user `home-control`, you can use `SQLALCHEMY_DATABASE_URI = "postgresql://home-control:/home-control"`.
- `SECRET_KEY = "notreallyasecret-pleasedontuse"`
  is the key used to sign the session cookie.
  For production, you want to set this to a random string.
  You can use `python3 -c 'import secrets; print(secrets.token_urlsafe())'` to generate suitable random string.
- `LOCAL_NET = "A.B.C.D/E"`
  allows a specific network given in CIDR notation to access Home Control features without being logged in.
  This is optional and will disable local access permission if not set.
- `MQTT_HOST = "1.2.3.4"`, `MQTT_USER = "username"`, `MQTT_PASS = "password"`
  configure the connection to your MQTT server.
- `BIND_IP = "127.0.0.1"`
  sets the local address to use for incoming connections for websocket and grafana.
  This is optional and will default to `127.0.0.1` if not set.
- `TIMEZONE="UTC"`
  defines the local time zone used for cron like timers.
  This is optional and will default to `UTC` if not set. 

## Running a test environment
For testing/development on a local machine you will need a working TLS setup for user authentication to work in the frontend.
This is needed as using cookies via a websocket only works in a "secure context".
A self-signed certificate won't work as no major browser allows for HTTPS security exceptions on websocket connections.
You can e.g., use `mkcert` to create a trusted certificate for your local machine.
You can use the `examples/stunnel.conf` file with `stunnel` to terminate the TLS and pass it on to the 
development webservers for the frontend, and the Home Control backend.
For `stunnel` you need to combine the private and public keys of your certificate before it can be used.

## Writing rules
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

Timers are function which are called based on a schedule. A function becomes a timer when it is passed as the function argument to the `timer.add_timer` function.
You must also pass a unique timer id as the first argument.
There are three types of schedules:
- Cron (following a set schedule)
- Absolute (`at` argument, the function is called at a specific timestamp)
- Relative (`interval` argument the function is called after the specified time has elapsed, repeatedly if wanted)

Timers can delete themselves by returning the string "DELETE".
Each timer can only have one of the modes active at the same time (`at`, `interval`, and `cron` keyword arguments).
Timers are stored in the database. They will be executed at the scheduled time or later, when the system backend is restarted, if it was not running at the originally scheduled time.

### Examples

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
    db = shared.db_session_factory()
    my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
    if event.state.status_bool:
       my_lamp.on()
    else:
        my_lamp.off()
    db.close()
```

Wouldn't it be nice, if the "My Lamp" switches automatically off, when we go to bed.
Let's use a cron based timer for it.

First, we need a function which switches off "My Lamp". 

```python
import timer
@rule("timer_switch_off_my_lamp")
def switch_off_my_lamp(event):
    db = shared.db_session_factory()
    my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
    my_lamp.off()
    db.close()
```

Then, we have to define a timer, which switches off "My Lamp" at 22:30 from Mon to Fri.
The timer is added with `timer.add_timer()`.
We put this function call in a function named `init_timers()`.
This ensures that the timer will be called by system backend.

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
    db = shared.db_session_factory()
    my_lamp = Thing("shelly", name="My Lamp").resolve(db)[0]
    if event.state == "S":
        my_lamp.on()
        timer.add_timer("timer_switch_off_my_lamp", at=datetime.datetime.now(tz)+datetime.timedelta(minutes=5))
    db.close()
```

