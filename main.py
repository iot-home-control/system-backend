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
import signal
import threading
import time
from queue import Empty, Queue
from typing import Optional
import math
from dataclasses import dataclass, asdict


import sqlalchemy.exc
from itsdangerous import URLSafeSerializer

import click
import paho.mqtt.client as mqttm
import websockets
import bcrypt

import config
import grafana
import models.things
import mq
import rules
import shared
import timer
from models.database import DataType, LastSeen, RuleState, State, Thing, ThingView, Trend, View, User

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
rule_executor: Optional[threading.Thread] = None
timer_checker: Optional[threading.Thread] = None
websocket: Optional[threading.Thread] = None
db_session_factory = None
rule_queue = Queue()
ws_queue = Queue()
ws_event_loop: Optional[asyncio.AbstractEventLoop] = None
connected_wss = set()
sessions = dict()

cookie_serializer = URLSafeSerializer(config.SECRET_KEY, "websocket")  # Param 2 is a salt/context-id. Not really important what is in there.


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


def rule_executer_thread(queue):
    rulelog.info("Staring up")
    db = shared.db_session_factory()
    rules.init(db)
    db.close()
    while not request_shutdown:
        try:
            event = queue.get(block=True, timeout=0.2)
            if not event:
                rulelog.error("event in queue is None")
                continue
            thing_id, thing_class, kind, data = event
            for rule in rules.triggers.get(thing_id, []):
                db = shared.db_session_factory()
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
                db.close()
            queue.task_done()
        except Empty:
            pass
        except Exception:
            rulelog.exception("Uncaught Execption in rule_executer_thread")
    rulelog.info("Shutting down")


def timer_checker_thread():
    timerlog.info("Starting up")
    while not request_shutdown:
        try:
            timer.process_timers()
            time.sleep(1)
        except Exception:
            timerlog.exception("Uncaught Execption in timer_checker_thread")


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
        except websockets.exceptions.ConnectionClosed:
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
    if thing.type in ['switch', 'shelly']:
        sw = db.query(Thing).get(thing_id)
        val = data.get("value")
        if val:
            sw.on()
        else:
            sw.off()
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
    db = shared.db_session_factory()
    time.sleep(0.2)

    try:
        if session.permission == "authenticated" or session.scope == "local":
            await websocket.send(json.dumps(dict(type="auth_ok", level=session.to_access_level())))
            known_things = db.query(Thing).order_by(Thing.id).all()
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
        db.close()

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
            db = shared.db_session_factory()
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
            else:
                wslog.warning("Unknown msg_type {}".format(msg_type))
            db.close()
        else:
            wslog.info("Client {} disconnected".format(websocket.remote_address))
            connected_wss.remove(websocket)
            del sessions[websocket]
    except websockets.exceptions.ConnectionClosed:
        connected_wss.remove(websocket)
        del sessions[websocket]
        wslog.warning(f"Cleaning up stale connection: {websocket.remote_address}")
        if db:
            db.close()


def ws_thread(queue):
    wslog.info("Starting up")
    logging.getLogger("websockets.protocol").setLevel(logging.INFO)
    logging.getLogger("websockets.server").setLevel(logging.INFO)
    try:
        global ws_event_loop
        ws_event_loop = asyncio.new_event_loop()
        # ws_event_loop.set_debug(True)
        asyncio.set_event_loop(ws_event_loop)
        ws_server = websockets.serve(handle_ws_connection, getattr(config, "BIND_IP", "127.0.0.1"), 8765)
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
        db = shared.db_session_factory()
        ts = [thing.get_state_topic() for thing in db.query(Thing).all()] + ["alive"]
        db.close()
        client.subscribe(list(zip(ts, [0] * len(ts))))


def on_mqtt_disconnect(client, userdata, rc):
    if rc == 0:
        mqttlog.info("Disconnected from MQTT broker")
    else:
        mqttlog.warning("Connection to MQTT broker lost. Reconnecting.")
        client.connect_async(config.MQTT_HOST)


def on_mqtt_message(client, userdata, message):
    try:
        db = shared.db_session_factory()
        if message.topic.startswith("alive"):
            device_id = message.payload.decode("ascii")
            LastSeen.update_last_seen(db, device_id)
        else:
            node_type, vnode, stop = message.topic.split("/", maxsplit=2)
            if node_type == "shellies":
                device_id = vnode
                vnode_id = stop.split("/")[-1]
                node_type = "shelly"
                if vnode.startswith("shellybutton1"):
                    node_type = "shellybutton"
                if stop.split("/")[0] == "ext_temperature":
                    print("found shelly_temperature")
                    node_type = "shelly_temperature"
                if stop.split("/")[0] == "ext_humidity":
                    node_type = "shelly_humidity"
            elif node_type == "FRISCHLUFT":
                device_id = vnode
                vnode_id = "0"
                node_type = "frischluftworks-co2"
            else:
                device_id, vnode_id = vnode.rsplit('-', maxsplit=1)
            thing = Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id)
            if not thing:
                return
            print("Thing {} {} sent new state".format(thing.type, thing.name))
            res = thing.process_status(db, message.payload.decode("ascii"))
            if res[2] == "state":
                msg = dict(type="states", states=[db.query(State).get(res[3]).to_dict()])
                asyncio.run_coroutine_threadsafe(send_to_all(json.dumps(msg, cls=JsonEncoder),
                                                             restrict_to_access_level=AccessLevel.Local), ws_event_loop)
                rule_queue.put(res)
            elif res[2] == "event":
                rule_queue.put(res)
            else:
                mqttlog.error(f"Malformed process_status response '{res}'")
        db.close()
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
    rule_executor.join()
    print("Rule Execution", end=", ")

    timer_checker.join()
    print("Timer Checker", end=", ")

    asyncio.run_coroutine_threadsafe(ws_shutdown(), ws_event_loop)
    websocket.join()
    print("WebSockets", end=", ")

    grafana.stop()
    print("Grafana API")

    logging.shutdown()


# noinspection PyUnusedLocal
def shutdown_sig(sig, frame):
    shutdown()


def reload():
    mq.stop()
    import models.database
    models.database.thing_state_cache.clear()
    db = shared.db_session_factory()
    for thing in db.query(Thing).all():
        thing.last_state(db)
    db.close()
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message)


# noinspection PyUnusedLocal
def reload_sig(sig, frame):
    reload()


@click.group()
def cli():
    pass


@cli.command('run')
def main():
    global rule_executor
    global timer_checker
    global websocket
    signal.signal(signal.SIGTERM, shutdown_sig)
    signal.signal(signal.SIGHUP, reload_sig)

    print("Starting:", end=" ")
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message)
    print("MQTT", end=", ")

    rule_executor = threading.Thread(target=rule_executer_thread, args=(rule_queue,))
    rule_executor.start()
    print("Rule Execution", end=", ")

    timer_checker = threading.Thread(target=timer_checker_thread)
    timer_checker.start()
    print("Timer Checker", end=", ")

    websocket = threading.Thread(target=ws_thread, args=(ws_queue,))
    websocket.start()
    print("WebSockets", end=", ")

    grafana.start(bind_addr=getattr(config, 'BIND_IP', '127.0.0.1'), prefix="/grafana")
    print("Grafana API")

    rules.init_timers()
    # local timers
    try:
        local_rules.init_timers()
    except NameError:  # no module
        pass
    except AttributeError:  # no function
        pass

    db = shared.db_session_factory()
    for thing in db.query(Thing).all():
        thing.last_state(db)
    db.close()

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
    (5, datetime.timedelta(days=7)),  # Keep 5 minute intervals for data between 7 days and 4 weeks
    (15, datetime.timedelta(weeks=4)),  # Keep 15 minute intervals for data between 4 weeks (1 month) and 52/2 weeks (6 months, half a year)
    (60, datetime.timedelta(weeks=52 / 2)),  # Keep 1 hour intervals for data between 6 montsh and 2 years
    (24 * 60, datetime.timedelta(weeks=52 * 2)),  # Keep 1 day intervals for data older than 2 years
]
dt_epsilon = datetime.timedelta(microseconds=1)


def collate_states_to_trends(db):
    """ Collates stored states into trends of the finest configured interval.

    This is done by iterating over all stored trends that are older than the single state retention time configured in the finest grained trend interval.
    Interation is done in reverse time order (from youngest to oldest) - starting at an interval boundary - so no partial intervals are created.
    Iteration is done on a per thing basis.
    """

    def collate_data(states):
        vmin = math.inf
        vmax = -math.inf
        vsum = 0
        for state in states:
            vmin = min(vmin, state.status_float)
            vmax = max(vmax, state.status_float)
            vsum += state.status_float

        vavg = vsum / len(states)
        return len(states), vmin, round(vavg, 1), vmax

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
                    samples, vmin, vavg, vmax = collate_data(data_bin)
                    data.append((current_interval, (samples, vmin, vavg, vmax)))
                    interval_end = (interval_start - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                    trend = Trend(thing_id=thing.id, interval=interval_length, start=current_interval, end=interval_end,
                                  samples=samples, t_min=vmin, t_avg=vavg, t_max=vmax)
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

    In contrast to `collate_states` this methods runs in bottom-up fashion i.e. from oldest to youngest trend.
    For easier code structure the trends are collated from finest to coarsests.
    In worst case the data is put firstly in the second finest bin and then in the next coarser bin and so on.
    This might need some time when running initial data collation or if data housekeeping was not run for a longer period.

    Within the loop for the trends the data of each thing is collected in a dictionary to avoid running over the data again and again.
    A bucket is closed when a trend outsinde the current interval is found.
    Closing the bucket adds the new trend to the database and removes the finer ones which were used to generate it.
    In the end there might be buckets which have not been closed. Their content is kept in uncollated in the database.
    """

    def collate_data(trends):
        vmin = math.inf
        vmax = -math.inf
        vsum = 0
        count = 0
        for trend in trends:
            vmin = min(vmin, trend.t_min)
            vmax = max(vmax, trend.t_max)
            vsum += trend.t_avg
            count += trend.samples
        vavg = vsum / len(trends)
        return (count, vmin, round(vavg, 1), vmax)

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
                interval_start[tid] = dt_to_interval_start(trend.start, cur_len.total_seconds() // 60).replace(
                    tzinfo=datetime.timezone.utc)
                interval_end[tid] = (interval_start[tid] + cur_len - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                interval_data[tid] = []
            end = interval_end[tid]
            if trend.start > end:
                samples, vmin, vavg, vmax = collate_data(interval_data[tid])
                coarser_trend = Trend(thing_id=trend.thing_id, interval=cur_len, start=interval_start[tid],
                                      end=interval_end[tid],
                                      samples=samples, t_min=vmin, t_avg=vavg, t_max=vmax)
                db.add(coarser_trend)
                added += 1
                removed += len(interval_data[tid])
                for t in interval_data[tid]:
                    db.delete(t)

                interval_start[tid] = dt_to_interval_start(trend.start, cur_len.total_seconds() // 60).replace(
                    tzinfo=datetime.timezone.utc)
                interval_end[tid] = (interval_start[tid] + cur_len - dt_epsilon).replace(tzinfo=datetime.timezone.utc)
                interval_data[tid] = []
            interval_data[tid].append(trend)
        db.commit()  # commit begin_nested
        hklog.debug(f"Collated {removed} trends of {prv_len} into {added} trends of {cur_len}")
    db.commit()  # commit transaction


@cli.command()
def database_housekeeping():
    db = shared.db_session_factory()

    hklog.info("Collate states to trends")
    collate_states_to_trends(db)
    hklog.info("Collate trends to coarser trends")
    collate_trends(db)
    hklog.info("Done")

    db.close()


@cli.command("add-user")
@click.argument("name", type=click.STRING)
@click.option("--display-name", type=click.STRING)
def add_user(name, display_name=None):
    db = shared.db_session_factory()
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
