#!/usr/bin/env python3
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

import asyncio
import datetime
import enum
import functools
import json
import logging
import math
import pathlib
import signal
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, asdict
from queue import Empty, Queue
from typing import List, Optional

import bcrypt
import click
import paho.mqtt.client as mqttm
import sqlalchemy.exc
import websockets
from itsdangerous import URLSafeSerializer

import builtin_rules
import config
import frontend_dev
import grafana
import models.things
import mq
import rules
import shared
import timer
from models.database import DataType, DeviceInfo, RuleState, State, Thing, Trend, View, User, Timer

try:
    import local_rules
except ModuleNotFoundError:
    pass

logging.basicConfig(level=logging.DEBUG)
mqttlog = logging.getLogger("mqtt")
rulelog = logging.getLogger("rule")
timerlog = logging.getLogger("timer")
wslog = logging.getLogger("websocket")
mqttlog.setLevel(logging.INFO)
hklog = logging.getLogger("housekeeping")

request_shutdown = False
did_shutdown = False
rule_executor_thread: Optional[threading.Thread] = None
timer_checker_thread: Optional[threading.Thread] = None
websocket_thread: Optional[threading.Thread] = None
rule_queue = Queue()
ws_event_loop: Optional[asyncio.AbstractEventLoop] = None
connected_wss = set()
sessions = dict()
current_mqtt_connect_subscribe_mid: Optional[int] = None

cookie_serializer = URLSafeSerializer(config.SECRET_KEY, "websocket")  # Param 2 is a salt/context-id. Not really important what is in there.

mqtt_topics = {}
TOPIC_LEAF = "<LEAF>"


def register_mqtt_topic(pattern, cls):
    cur = mqtt_topics
    parts = pattern.split('/')
    for i, part in enumerate(parts):
        cur.setdefault(part, dict())
        cur = cur[part]
        if i+1 >= len(parts):
            if TOPIC_LEAF in cur:
                raise ValueError(f"Can't register {cls} with pattern {pattern}: Already registered on {cur[TOPIC_LEAF]}.")
            cur[TOPIC_LEAF] = cls


def register_mqtt_topics():
    for name, cls in models.things.thing_type_table.items():
        if not getattr(cls, 'get_mqtt_subscriptions'):
            continue
        try:
            topics = cls.get_mqtt_subscriptions()
            if not isinstance(topics, tuple):
                mqttlog.warning(f"{cls}.get_mqtt_subscriptions didn't return a tuple but {type(topics)}.")
                continue
            for topic in topics:
                register_mqtt_topic(topic, cls)
        except ValueError as e:
            mqttlog.exception(e)


def get_mqtt_topics():
    ts = []

    def get_topic(cur, t):
        if not isinstance(cur, dict):
            ts.append("/".join(t))
        else:
            for key, value in cur.items():
                if key == TOPIC_LEAF:
                    get_topic(value, t)
                else:
                    get_topic(value, t + [key])

    get_topic(mqtt_topics, [])
    return ts


def get_thing_cls(mqtt_topic: List[str]):
    cur: Optional[dict] = mqtt_topics
    for level in mqtt_topic:
        cur = cur.get(level, cur.get("+", None))
        if cur is None:
            return None
    return cur.get(TOPIC_LEAF)


class AccessLevel(enum.IntEnum):
    Unauthenticated = 0
    Local = 1
    Authenticated = 2


@dataclass
class Session:
    permission: str
    scope: str

    def to_access_level(self):
        if self.permission == "authenticated":
            return AccessLevel.Authenticated
        elif self.permission == "unauthenticated" and self.scope == "local":
            return AccessLevel.Local
        else:
            return AccessLevel.Unauthenticated

    def check_access_level(self, level: AccessLevel):
        if level == AccessLevel.Unauthenticated:
            return True
        session_authenticated = self.permission == "authenticated"
        session_local = self.scope == "local"
        if session_authenticated or (level == AccessLevel.Local and session_local):
            return True
        return False


def rule_executor_thread_main(queue):
    rulelog.info("Staring up")
    with shared.db_session_factory() as db:
        rules.init(db)
    while not request_shutdown:
        try:
            event = queue.get(block=True, timeout=0.2)
            if not event:
                rulelog.error("event in queue is None")
                continue
            thing_id, thing_class, kind, data = event
            for rule in rules.triggers.get(thing_id, []):
                with shared.db_session_factory() as db:
                    rulestate = db.query(RuleState).get(rules.all_rules[rule])
                    if rulestate and not rulestate.enabled:
                        continue
                    try:
                        if kind == "state":
                            revent = rules.RuleEvent(rules.EventSource.Trigger, db.query(thing_class).get(thing_id),
                                                     db.query(State).get(data))
                        elif kind == "event":
                            revent = rules.RuleEvent(rules.EventSource.Event, db.query(thing_class).get(thing_id), data)
                        else:
                            rulelog.error(f"Unsupported rule event kind: {kind}")
                            break
                        rule(revent)
                        db.commit()
                    except Exception:
                        rulelog.exception("Error while executing rule {}".format(rules.all_rules[rule]))
            queue.task_done()
        except Empty:
            pass
        except Exception:
            rulelog.exception("Uncaught Exception in rule_executer_thread")
    rulelog.info("Shutting down")


def timer_checker_thread_main():
    timerlog.info("Starting up")
    while not request_shutdown:
        try:
            timer.process_timers()
            time.sleep(1)
        except Exception:
            timerlog.exception("Uncaught Exception in timer_checker_thread")


async def send_to_all(msg, restrict_to_access_level=None):
    if not connected_wss:
        return

    async def sender(ws):
        try:
            if restrict_to_access_level:
                session = sessions.get(ws)
                if not session or session.check_access_level(restrict_to_access_level):
                    await ws.send(msg)
            else:
                await ws.send(msg)
        except websockets.ConnectionClosed:
            pass

    await asyncio.wait([asyncio.create_task(sender(ws)) for ws in connected_wss])


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)


def check_access(level=AccessLevel.Authenticated):
    def wrapper(f):
        @functools.wraps(f)
        async def check(db, websocket, *args, **kwargs):
            session = sessions.get(websocket)
            if not session:
                await websocket.send(json.dumps(dict(type="auth_required")))
                return

            if session.check_access_level(level):
                await f(db, websocket, *args, **kwargs)
            else:
                await websocket.send(json.dumps(dict(type="auth_required")))
        return check
    return wrapper


@check_access(level=AccessLevel.Local)
async def ws_type_command(db, websocket, data):
    thing_id = data.get("id")
    thing = db.query(Thing).get(thing_id)
    if not thing:
        wslog.warning("Thing {} is unknown".format(thing_id))
        return
    if thing.type in ['switch', 'shelly', 'shellyplus']:
        val = data.get("value")
        if val:
            thing.on()
        else:
            thing.off()
    elif thing.type in ["shellytrv"]:
        val = data.get("value")
        thing.send_value(val)
    else:
        wslog.warning("Unsupported type for command: '{}'".format(thing.type))


@check_access(level=AccessLevel.Local)
async def ws_type_last_seen(db, websocket, data):
    things = db.query(Thing).all()
    last_seen = {thing.id: thing.last_seen.isoformat() if thing.last_seen else None for thing in things}
    msg = dict(type="last_seen", last_seen=last_seen)
    await websocket.send(json.dumps(msg))


@check_access(level=AccessLevel.Authenticated)
async def ws_type_create_or_edit(db, websocket, data):
    thing_id = data.get("id")
    thing = db.query(Thing).get(thing_id) if thing_id else None

    data = dict(id=None,
                views=[dict(value=v.id, text=v.name) for v in db.query(View).order_by(View.name, View.id).all()],
                types=[dict(value=k, text=cls.display_name()) for k, cls in
                       sorted(models.things.thing_type_table.items()) if cls.display_name()],
                thing_views=[],
                thing_type=None,
                visible=True,
                name='',
                device_id='',
                vnode=0
                )

    if thing:  # Edit
        data['id'] = thing.id
        data['thing_views'] = [view.id for view in thing.views.all()]
        data['thing_type'] = thing.type
        data['name'] = thing.name
        data['device_id'] = thing.device_id
        data['vnode'] = thing.vnode_id
        data['visible'] = thing.visible
        data['ordering'] = thing.ordering

    await websocket.send(json.dumps(dict(type="edit_data", kind="thing", data=data)))


@check_access(level=AccessLevel.Authenticated)
async def ws_type_edit_save(db, websocket, data):
    kind = data.get('editing')
    if kind == 'thing':
        data = data.get('data')
        thing = db.query(Thing).get(data["id"]) if data.get("id") else None
        new_thing = not thing
        if new_thing:
            thing = Thing()
            db.add(thing)
        thing.name = data['name']
        if new_thing:
            thing.type = data['thing_type']
        thing.device_id = data['device_id']
        thing.vnode_id = data['vnode']
        thing.visible = data['visible']
        ordering = data.get("ordering")
        if ordering is not None and ordering.isnumeric():
            thing.ordering = int(ordering)
        else:
            thing.ordering = None
        prev_views = set(thing.views)
        thing.views = [db.query(View).get(int(e['value'])) for e in data['views']]
        db.commit()
        await websocket.send(json.dumps(dict(type="edit_ok")))
        await send_to_all(json.dumps(dict(type="things", things=[thing.to_dict()])),
                          restrict_to_access_level=AccessLevel.Local)
        if prev_views != set(thing.views):
            views_query = db.query(View).order_by(View.name, View.id).all()
            known_things = db.query(Thing).order_by(Thing.id).all()
            views = dict(All=[thing.id for thing in known_things])
            views.update({view.name: [thing.id for thing in view.things] for view in views_query})
            await send_to_all(json.dumps(dict(type="views", views=views)),
                              restrict_to_access_level=AccessLevel.Local)
        if new_thing:
            mq.subscribe(thing.get_state_topic())


async def new_ws_session(websocket):
    import ipaddress
    real_peer_address = websocket.request_headers.get("X-Real-IP", websocket.remote_address[0])
    addr = ipaddress.ip_address(real_peer_address)

    addr_is_in_local_net = False
    if hasattr(config, 'LOCAL_NET') and config.LOCAL_NET:
        addr_is_in_local_net = addr in ipaddress.ip_network(config.LOCAL_NET)

    addr_scope = "remote"
    if addr.is_private and (addr_is_in_local_net or addr.is_loopback):
        addr_scope = "local"

    session = Session(permission="unauthenticated", scope=addr_scope)
    await websocket.send(json.dumps(dict(type="cookie", name="auth", value=cookie_serializer.dumps(asdict(session)),
                                         max_age=180*24*60*60)))
    return session


@check_access(level=AccessLevel.Unauthenticated)
async def ws_authenticate(db, websocket, data, session):
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        await websocket.send(json.dumps(dict(type="auth_failed")))

    user = db.query(User).filter_by(name=username).one_or_none()
    if not user:
        await websocket.send(json.dumps(dict(type="auth_failed")))
        return

    if bcrypt.checkpw(password.encode(), user.pwhash.encode()):
        session.permission = "authenticated"
        await websocket.send(json.dumps(dict(type="auth_ok")))
        await websocket.send(json.dumps(dict(type="cookie", name="auth",
                                             value=cookie_serializer.dumps(asdict(session)),
                                             max_age=180*24*60*60)))
        await websocket.close()
    else:
        await websocket.send(json.dumps(dict(type="auth_failed")))


@check_access(level=AccessLevel.Authenticated)
async def send_rules(db, websocket, data):
    # expected format of data
    # {"rule_name": {enabled: True / False / Null}
    if data.get("data"):
        # TODO: this is user defined content, we should be aware of this
        for rule_name, rule_state in data.get("data").items():
            if rule_state and rule_state.get("enabled") is not None:
                current_rule_state = db.query(RuleState).get(rule_name)
                if current_rule_state is not None:
                    current_rule_state.enabled = rule_state.get("enabled")
                    continue
                current_rule_state = RuleState()
                current_rule_state.id = rule_name
                current_rule_state.enabled = rule_state.get("enabled")
                db.add(current_rule_state)
        db.commit()

    all_rules = []
    for rule in rules.all_rules.values():
        rule_state = db.query(RuleState).get(rule)
        enabled = rule_state.enabled if rule_state else None
        all_rules.append({"name": rule, "state": enabled})
    await websocket.send(json.dumps(dict(type="rules", value=all_rules)))


async def handle_ws_connection(websocket, path):
    wslog.info("Client {} connected".format(websocket.remote_address))
    cookie_header = websocket.request_headers.get("Cookie", "")
    if not cookie_header:
        session = await new_ws_session(websocket)
    else:
        import http.cookies
        cookies = http.cookies.SimpleCookie(cookie_header)
        if "auth" in cookies:
            from itsdangerous import BadSignature
            try:
                session_data = cookie_serializer.loads(cookies["auth"].value)
                session = Session(**session_data)
            except BadSignature:
                session = await new_ws_session(websocket)
            except TypeError as e:
                wslog.exception(f"Failed to restore session data={session_data}")
                session = await new_ws_session(websocket)
        else:
            session = await new_ws_session(websocket)

    connected_wss.add(websocket)
    sessions[websocket] = session

    time.sleep(0.2)

    try:
        if session.permission == "authenticated" or session.scope == "local":
            with shared.db_session_factory() as db:
                await websocket.send(json.dumps(dict(type="auth_ok", level=session.to_access_level())))
                known_things = db.query(Thing).order_by(Thing.ordering, Thing.name).all()
                msg = dict(type="things", things=[t.to_dict() for t in known_things])
                await websocket.send(json.dumps(msg))

                states = [s for s in (t.last_state(db) for t in known_things) if s]
                msg = dict(type="states", states=[s.to_dict() for s in states])
                await websocket.send(json.dumps(msg, cls=JsonEncoder))

                views_query = db.query(View).order_by(View.name, View.id).all()
                views = dict(All=[thing.id for thing in known_things])
                views.update({view.name: [thing.id for thing in view.things] for view in views_query})
                msg = dict(type="views", views=views)
                await websocket.send(json.dumps(msg))

        async for message in websocket:
            try:
                data = json.loads(message)
            except json.JSONDecodeError as err:
                wslog.warning(
                    "Discarding message from {}: Can't decode as JSON ({})".format(websocket.remote_address, str(err)))
                continue
            if not isinstance(data, dict):
                wslog.warning(
                    "Discarding message from {}: Not a JSON object: {}".format(websocket.remote_address, data))
                continue
            msg_type = data.get("type")
            if not msg_type:
                wslog.warning("Discarding message from {}: Missing \"type\" field".format(websocket.remote_address))
                continue
            with shared.db_session_factory() as db:
                if msg_type == "command":
                    await ws_type_command(db, websocket, data)
                elif msg_type == "last_seen":
                    await ws_type_last_seen(db, websocket, data)
                elif msg_type == "create_or_edit":
                    await ws_type_create_or_edit(db, websocket, data)
                elif msg_type == "edit_save":
                    await ws_type_edit_save(db, websocket, data)
                elif msg_type == "authenticate":
                    await ws_authenticate(db, websocket, data, session)
                elif msg_type == "rules":
                    await send_rules(db, websocket, data)
                else:
                    wslog.warning("Unknown msg_type {}".format(msg_type))
        else:
            wslog.info("Client {} disconnected".format(websocket.remote_address))
            connected_wss.remove(websocket)
            del sessions[websocket]
    except websockets.ConnectionClosed:
        connected_wss.remove(websocket)
        del sessions[websocket]
        wslog.warning(f"Cleaning up stale connection: {websocket.remote_address}")


def ws_thread_main(ssl_data):
    wslog.info("Starting up")
    logging.getLogger("websockets.protocol").setLevel(logging.INFO)
    logging.getLogger("websockets.server").setLevel(logging.INFO)

    bind_ip = getattr(config, "BIND_IP", "127.0.0.1")
    port = 8765

    use_ssl, ssl_cert, ssl_key = ssl_data
    ssl_context = None
    if use_ssl:
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            wslog.info("Enabling SSL")
            ssl_context.load_cert_chain(ssl_cert, ssl_key)
            port = 8766
        except ssl.SSLError as e:
            wslog.warning(f"Failed to enable SSL: {e}")

    try:
        global ws_event_loop
        ws_event_loop = asyncio.new_event_loop()
        # ws_event_loop.set_debug(True)
        asyncio.set_event_loop(ws_event_loop)
        ws_server = websockets.serve(handle_ws_connection, bind_ip, port, ssl=ssl_context)
        wslog.info(f"Listening on {bind_ip}:{port}")
        ws_event_loop.run_until_complete(ws_server)
        ws_event_loop.run_forever()
        wslog.info("Shutting down")
    except Exception:
        wslog.exception("Uncaught Exception in ws_thread")


async def ws_shutdown():
    if connected_wss:
        await asyncio.wait([asyncio.create_task(ws.close(reason="Shutting down")) for ws in connected_wss])
    ws_event_loop.stop()
    await ws_event_loop.shutdown_asyncgens()


def on_mqtt_connect(client, userdata, flags, rc):
    if rc != 0:
        mqttlog.error("Can't connect to MQTT broker: %s",
                      mqttm.connack_string(rc))
        shutdown()
        return
    else:
        mqttlog.info("Connected to MQTT broker. Subscribing topics.")
        ts = get_mqtt_topics() + ["alive", "shellies/announce"]
        global current_mqtt_connect_subscribe_mid
        _, current_mqtt_connect_subscribe_mid = client.subscribe(list(zip(ts, [0] * len(ts))))


def on_mqtt_disconnect(client, userdata, rc):
    if rc == 0:
        mqttlog.info("Disconnected from MQTT broker")
    else:
        mqttlog.warning("Connection to MQTT broker lost. Reconnecting.")
        client.connect_async(config.MQTT_HOST)


def on_mqtt_subscribe(client, _userdata, mid, _reason_codes_or_qos, _properties=None):
    global current_mqtt_connect_subscribe_mid
    if current_mqtt_connect_subscribe_mid == mid:
        current_mqtt_connect_subscribe_mid = None
        client.publish("shellies/command", "announce")


def on_mqtt_message(client, userdata, message):
    try:
        with shared.db_session_factory() as db:
            if message.topic.startswith("alive"):
                infos = dict()
                try:
                    decoded = json.loads(message.payload.decode("ascii"))
                    device_id = decoded.pop("device_id")
                    infos["ip_addr"] = decoded.pop("local_ip", None)
                    infos["firmware_version"] = decoded.pop("git_version", None)
                    infos["is_updatable"] = decoded.pop("update_available", None)
                    infos.update(decoded)
                except json.JSONDecodeError:
                    device_id = message.payload.decode("ascii")

                DeviceInfo.update_device_info(db, device_id, **infos)
            elif message.topic.startswith("shellies/announce"):
                infos = dict()
                try:
                    decoded = json.loads(message.payload.decode("ascii"))
                    device_id = decoded.get("id")
                    infos["ip_addr"] = decoded.get("ip", None)
                    infos["firmware_version"] = decoded.get("fw_id", decoded.get("fw_ver", None))
                    infos["is_updatable"] = decoded.get("new_fw", None)
                except json.JSONDecodeError:
                    return
                DeviceInfo.update_device_info(db, device_id, **infos)
            else:
                split_topic = message.topic.split("/")
                thing_cls = get_thing_cls(split_topic)
                if thing_cls is None:
                    return
                thing, data = thing_cls.get_by_mqtt_topic(db, split_topic)
                if not thing:
                    return

                def process_thing_status(thing):
                    if getattr(config, 'LOG_NEW_STATES', True):
                        print("Thing {} {} sent new state".format(thing.type, thing.name))
                    res = thing.process_status(db, message.payload.decode("ascii"), data)
                    if res[2] == "state":
                        msg = dict(type="states", states=[db.query(State).get(res[3]).to_dict()])
                        asyncio.run_coroutine_threadsafe(send_to_all(json.dumps(msg, cls=JsonEncoder),
                                                                     restrict_to_access_level=AccessLevel.Local),
                                                         ws_event_loop)
                        rule_queue.put(res)
                    elif res[2] == "event":
                        rule_queue.put(res)
                    else:
                        mqttlog.error(f"Malformed process_status response '{res}'")

                if isinstance(thing, Iterable):
                    for t in thing:
                        process_thing_status(t)
                else:
                    process_thing_status(thing)

    except Exception:
        mqttlog.exception("Uncaught exception in on_mqtt_message")


def shutdown():
    global did_shutdown
    global request_shutdown
    if did_shutdown:
        return
    did_shutdown = True
    print("Shutting down:", end=" ")
    mq.stop()
    print("MQTT", end=", ")

    request_shutdown = True
    rule_executor_thread.join()
    print("Rule Execution", end=", ")

    timer_checker_thread.join()
    print("Timer Checker", end=", ")

    asyncio.run_coroutine_threadsafe(ws_shutdown(), ws_event_loop)
    websocket_thread.join()
    print("WebSockets", end=", ")

    frontend_dev_running = frontend_dev.running()

    grafana.stop()
    print("Grafana API", end=", " if frontend_dev_running else None)

    if frontend_dev_running:
        frontend_dev.stop()
        print("Frontend Webserver")

    logging.shutdown()


# noinspection PyUnusedLocal
def shutdown_sig(sig, frame):
    shutdown()


def reload():
    mq.stop()
    import models.database
    models.database.thing_state_cache.clear()
    with shared.db_session_factory() as db:
        for thing in db.query(Thing).all():
            thing.last_state(db)
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message, on_mqtt_subscribe)


# noinspection PyUnusedLocal
def reload_sig(sig, frame):
    reload()


@click.group()
def cli():
    pass


@cli.command('run')
@click.option('ssl_cert', '--cert', type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path))
@click.option('ssl_key', '--key', type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path))
@click.option('frontend_dir', '--serve-frontend', type=click.Path(exists=True, file_okay=False, path_type=pathlib.Path))
def main(ssl_cert: Optional[pathlib.Path], ssl_key: Optional[pathlib.Path], frontend_dir: Optional[pathlib.Path]):
    global rule_executor_thread
    global timer_checker_thread
    global websocket_thread
    signal.signal(signal.SIGTERM, shutdown_sig)
    signal.signal(signal.SIGHUP, reload_sig)

    use_ssl = ssl_cert is not None

    print("Starting:", end=" ")
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message, on_mqtt_subscribe)
    register_mqtt_topics()
    print("MQTT", end=", ")

    rule_executor_thread = threading.Thread(target=rule_executor_thread_main, args=(rule_queue,))
    rule_executor_thread.start()
    print("Rule Execution", end=", ")

    timer_checker_thread = threading.Thread(target=timer_checker_thread_main)
    timer_checker_thread.start()
    print("Timer Checker", end=", ")

    websocket_thread = threading.Thread(target=ws_thread_main, args=((use_ssl, ssl_cert, ssl_key),))
    websocket_thread.start()
    print("WebSockets", end=", ")

    grafana.start(bind_addr=getattr(config, 'BIND_IP', '127.0.0.1'), prefix="/grafana")
    print("Grafana API", end=', ' if frontend_dir else None)
    with shared.db_session_factory() as db:
        db.query(Timer).filter(Timer.auto_delete == True).delete()
        db.commit()

    if frontend_dir:
        frontend_dev.start(frontend_dir, getattr(config, 'BIND_IP', '127.0.0.1'), 8080, (use_ssl, ssl_cert, ssl_key))
        print("Frontend Webserver")

    rules.init_timers()
    builtin_rules.init_timers()
    # local timers
    try:
        local_rules.init_timers()
    except NameError:  # no module
        pass
    except AttributeError:  # no function
        pass

    with shared.db_session_factory() as db:
        for thing in db.query(Thing).all():
            thing.last_state(db)

    try:
        while not request_shutdown:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    shutdown()


def dt_to_interval_start(dt: datetime.datetime, minutes: int) -> datetime.datetime:
    n = minutes * 60
    ts = int(dt.timestamp())
    return datetime.datetime.fromtimestamp((ts // n) * n)


# Interval length in minutes, aggregate when older than x minutes
intervals = [
    # Keep raw state data for 7 days
    (5, datetime.timedelta(days=7)),  # Keep 5-minute intervals for data between 7 days and 4 weeks
    (15, datetime.timedelta(weeks=4)),  # Keep 15-minute intervals for data between 4 weeks (1 month) and 52/2 weeks (6 months, half a year)
    (60, datetime.timedelta(weeks=52 / 2)),  # Keep 1-hour intervals for data between 6 months and 2 years
    # (24 * 60, datetime.timedelta(weeks=52 * 2)),  # Keep 1-day intervals for data older than 2 years
]
dt_epsilon = datetime.timedelta(microseconds=1)


def collate_states_to_trends(db):
    """ Collates stored states into trends of the finest configured interval.

    This is done by iterating over all stored trends that are older than the single state retention time configured in
    the finest-grained trend interval.
    Interation is done in reverse time order (from youngest to oldest) - starting at an interval boundary - so no
    partial intervals are created.
    Iteration is done on a per-thing basis.
    """

    def collate_data(state_data):
        v_min = math.inf
        v_max = -math.inf
        v_sum = 0
        for entry in state_data:
            v_min = min(v_min, entry.status_float)
            v_max = max(v_max, entry.status_float)
            v_sum += entry.status_float

        v_avg = v_sum / len(state_data)
        return len(state_data), v_min, round(v_avg, 1), v_max

    now = datetime.datetime.now(tz=datetime.timezone.utc)

    things = db.query(Thing).all()
    for thing in things:
        if thing.get_data_type() != DataType.Float:
            continue
        db.begin_nested()
        interval_start = now - intervals[0][1]
        interval_start = dt_to_interval_start(interval_start, intervals[0][0])
        interval_length = datetime.timedelta(minutes=intervals[0][0])
        current_interval = (interval_start - interval_length).replace(tzinfo=datetime.timezone.utc)

        states = db.query(State).filter(State.thing_id == thing.id, State.when < interval_start).order_by(
            State.when.desc()).all()
        data = []
        data_bin = []

        removed = 0
        added = 0
        for state in states:
            if state.when < current_interval:
                if len(data_bin):
                    samples, t_min, t_avg, t_max = collate_data(data_bin)
                    data.append((current_interval, (samples, t_min, t_avg, t_max)))
                    interval_end = (interval_start - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                    trend = Trend(thing_id=thing.id, interval=interval_length, start=current_interval, end=interval_end,
                                  samples=samples, t_min=t_min, t_avg=t_avg, t_max=t_max)
                    db.add(trend)
                    added += 1
                    data_bin = []
                while state.when < current_interval:
                    interval_start = current_interval
                    current_interval = (current_interval - interval_length).replace(tzinfo=datetime.timezone.utc)
            if state.when >= current_interval:
                data_bin.append(state)
                db.delete(state)
                removed += 1
        db.commit()
        hklog.debug(f"Thing ({thing.id}, {thing.type}) {thing.name}: Collated {removed} states into {added} trends")
    db.commit()


def collate_trends(db):
    """ Collate trends that are old enough into coarser trends based on configured intervals.

    In contrast to `collate_states` this method runs in bottom-up fashion i.e. from oldest to youngest trend.
    For easier code structure the trends are collated from finest to coarsest.
    In worst case the data is put firstly in the second-finest bin and then in the next coarser bin and so on.
    This might need some time when running initial data collation or if data housekeeping was not run for a longer
    period.

    Within the loop for the trends the data of each thing is collected in a dictionary to avoid running over the data
    again and again.
    A bucket is closed when a trend outside the current interval is found.
    Closing the bucket adds the new trend to the database and removes the finer ones which were used to generate it.
    In the end there might be buckets which have not been closed. Their content is kept in uncollated in the database.
    """

    def collate_data(trends):
        v_min = math.inf
        v_max = -math.inf
        v_sum = 0
        count = 0
        for entry in trends:
            v_min = min(v_min, entry.t_min)
            v_max = max(v_max, entry.t_max)
            v_sum += entry.t_avg
            count += entry.samples
        v_avg = v_sum / len(trends)
        return count, v_min, round(v_avg, 1), v_max

    for idx in range(1, len(intervals)):
        prv_len = datetime.timedelta(minutes=intervals[idx - 1][0])
        cur_len = datetime.timedelta(minutes=intervals[idx][0])
        keep_after = (datetime.datetime.now() - intervals[idx][1]).replace(tzinfo=datetime.timezone.utc)
        interval_start = {}
        interval_end = {}
        interval_data = {}

        removed = 0
        added = 0
        db.begin_nested()
        for trend in db.query(Trend).filter(Trend.interval == prv_len and Trend.start < keep_after).order_by(
                Trend.start.asc()).all():
            tid = trend.thing_id
            if interval_start.get(tid) is None:
                interval_start[tid] = dt_to_interval_start(trend.start, int(cur_len.total_seconds() // 60)).replace(
                    tzinfo=datetime.timezone.utc)
                interval_end[tid] = (interval_start[tid] + cur_len - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                interval_data[tid] = []
            end = interval_end[tid]
            if trend.start > end:
                samples, t_min, t_avg, t_max = collate_data(interval_data[tid])
                coarser_trend = Trend(thing_id=trend.thing_id, interval=cur_len, start=interval_start[tid],
                                      end=interval_end[tid],
                                      samples=samples, t_min=t_min, t_avg=t_avg, t_max=t_max)
                db.add(coarser_trend)
                added += 1
                removed += len(interval_data[tid])
                for t in interval_data[tid]:
                    db.delete(t)

                interval_start[tid] = dt_to_interval_start(trend.start, int(cur_len.total_seconds() // 60)).replace(
                    tzinfo=datetime.timezone.utc)
                interval_end[tid] = (interval_start[tid] + cur_len - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                interval_data[tid] = []
            interval_data[tid].append(trend)
        db.commit()  # commit begin_nested
        hklog.debug(f"Collated {removed} trends of {prv_len} into {added} trends of {cur_len}")
    db.commit()  # commit transaction


@cli.command()
def database_housekeeping():
    with shared.db_session_factory() as db:
        hklog.info("Collate states to trends")
        collate_states_to_trends(db)
        hklog.info("Collate trends to coarser trends")
        collate_trends(db)
        hklog.info("Done")


@cli.command("add-user")
@click.argument("name", type=click.STRING)
@click.option("--display-name", type=click.STRING)
def add_user(name, display_name=None):
    with shared.db_session_factory() as db:
        pw = click.prompt("Password", hide_input=True, type=click.STRING)
        pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        user = User(name=name, display_name=display_name, pwhash=pw_hash.decode("ascii"))
        db.add(user)
        try:
            db.commit()
        except sqlalchemy.exc.IntegrityError:
            print("Username not available")


if __name__ == "__main__":
    cli()
