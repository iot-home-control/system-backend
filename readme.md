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

We will assume that the install dir is /opt/home-control

Unpack the release file to /opt/home-control/system-backend

Create a virtual env 

`python3 -m venv venv`

install requirements 

`./venv/bin/pip install -r requirements.txt`

copy example config 

`cp config.example.py config.py`

and edit the variables in config according to description in it.

You can run the Home Control System Backend with
`./venv/bin/python main.py run`

We provide a systemd service file.
