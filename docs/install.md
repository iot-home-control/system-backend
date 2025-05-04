# Installation Guide
## Requirements
Home Control is a Python project and as such should be able to run on most platforms supported by Python 3.
On your system you should install (or should have available on your network):
- Python3 (at least Python 3.9)
- Python-Virtualenv (python3-venv)
- PostgreSQL.  
  MySQL might also work (you need to install a database driver manually. 
  See [SQLAlchemy documentation](https://docs.sqlalchemy.org/en/12/orm/tutorial.html#connecting).
  However, we have not tested it.)
- A MQTT message queue e.g., mosquitto
- A webserver, which can handle websockets (we recommend nginx)

Optionally, you can also install:
- grafana

## Setup
In the following we assume all non-absolute paths will be relative to the installation directory.
In all our example configuration files we assume `/opt/home-control/system-backend` to be the installation location.

1. Unpack the downloaded release file (or clone this repository)  to the installation directory.

1. Create a Python virtual environment in the installation directory (it will be in a folder named venv)  
   `python3 -m venv venv`.
1. *Optional:* Activate the virtualenv by running `. venv/bin/activate`.
   If you do this you can leave out the `venv/bin/` in future commands.
   The virtualenv can be deactivated with `deactivate` after you're done.   
1. Install system-backend into the virtualenv
   `venv/bin/pip install -e .`.
1. Create an empty database (and a database user) for Home Control.
   How to do that depends on your database server.
1. Create a config file for Home Control (you can copy `config.example.py` to `config.py` for a quick start) and fill it out.
   See [the configuration section](#Configuration) for more information.
1. Initialize the database by running  
   `venv/bin/alembic upgrade head`.
1. We recommend configuring your webserver to forward WebSocket connections to the location `/ws` to Home Control.
   We provide a nginx configuration snippet for this in `examples/`.
   To configure Home Control via the web interface you'll also need a working TLS setup so this is a good point to also configure your web server for it.
1. Create one or more users. Users are necessary to add and configure things via the web interface.
   `venv/bin/python main.py add-user <USERNAME>`. While running the command will ask you for the user's password.
1. Start Home Control by either:
    - running `venv/bin/python main.py run` in your terminal.
    - installing and enabling the systemd unit file included in the `examples/` directory.
1. *Optional:* Set up automatic database housekeeping.
   It is used to aggregate data after a while and provide long term trends for your data.
   Configure your system to run `venv/bin/python main.py database-housekeeping` regularly, for example 4 times a day, by setting up a cronjob or installing the provided systemd timer unit in `examples/`.

## Configuration
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
- `FRONTEND_PORT = 8080`
  configures the HTTP port for the development frontend server.
- `WS_PORT = 8765`
  configures the port where the websocket listens.
- `API_PORT = 8000`
  configure the port where the Grafana endpoint and config server terminate.
- `TIMEZONE="UTC"`
  defines the local time zone used for cron like timers.
  This is optional and will default to `UTC` if not set. 

