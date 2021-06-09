# Home Control

Home Control has 3 Components
- the System Backend
- the Web Frontend
- the firmware

The System Backend connects to a Message Queue (MQTT) to get state messages of things. A received state is saved to a database and sent to all active web frontends via a web socket connection.
The Backend provides also a Grafana data source.
If you like the system backend can collate the collected data into trends.

## Install Guide

You must have installed at least:
- python3.7
- python3-venv
- a database sqlite, mariadb or postgresql (we recommend the latter one)
- a mqtt message queue e.g. mosquitto
- a webserver, which can handle websockets (we recommend nginx)

Optionally, you can install additionally:
- grafana

For authentication you need a valid TLS setup.

We will assume that the Home-Control is installed in /opt/home-control

Unpack the release file to /opt/home-control/system-backend

Create a virtual env 

`python3 -m venv venv`

install requirements 

`./venv/bin/pip install -r requirements.txt`

copy example config 

`cp config.example.py config.py`

and edit the variables in config according to description in it.

You can run the Home Control System Backend with
`./venv/bin/python main.py run`.

We provide a systemd service file.

You can call the Home Control House Cleaning with
`./venv/bin/python main.py database-housekeeping`.
See the files in `examples/` for information on how to run it regularly with a systemd timer unit.


## Writing rules
You can write your own rules by creating a `local_rules.py` file in the installation directory.
There are examples in `local_rules.py.example` which is also

We have rules and timers.
Rules are functions which are called when either
    - a timer expires (see later),
    - a thing specified as rule trigger changes state
    - another event happens, such as button presses or scene changes.

A function becomes a rule if it has the `@rule` decorator. The rule decorator take a rule identifier as the first argument. Please note that rule identifiers must be unique.
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
Timers are stored in the database, so they will be executed if the system backend gets restarted or is not running at the scheduled time of execution.

## Running a test environment

For testing on a local machine you need a working TLS setup. This is needed for authentication since using cookies via a websocket requires it.
You can e.g., use `mkcert` to create a trusted certificate for your local machine.
You can use the `examples/stunnel.conf` file with `stunnel` to terminate the TLS and pass it on to the development webservers for the frontend and the Home-Control backend.
For `stunnel` you need to combine the private and public keys of your certificate before it can be used.
