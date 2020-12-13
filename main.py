#!/usr/bin/env python3

import mq
import paho.mqtt.client as mqttm
import shared
from models.database import Thing, State, View, LastSeen, RuleState
import logging
import signal
import threading
import time
import config
import datetime
from queue import Queue, Empty
import models.things
import rules
import timer
import websockets
import asyncio
import json
import grafana
from typing import Optional

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
            thing_id, thing_class, state_id = event
            for rule in rules.triggers.get(thing_id, []):
                db = shared.db_session_factory()
                rulestate = db.query(RuleState).get(rules.all_rules[rule])
                if rulestate and not rulestate.enabled:
                    continue
                try:
                    revent = rules.RuleEvent(rules.EventSource.Trigger, db.query(thing_class).get(thing_id), db.query(State).get(state_id))
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


async def send_to_all(msg):
    if not connected_wss:
        return

    async def sender(ws):
        try:
            await ws.send(msg)
        except websockets.exceptions.ConnectionClosed:
            pass

    await asyncio.wait([sender(ws) for ws in connected_wss])


class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)


async def handle_ws_connection(websocket, path):
    wslog.info("Client {} connected".format(websocket.remote_address))
    connected_wss.add(websocket)
    db = shared.db_session_factory()
    time.sleep(0.2)

    try:
        known_things = db.query(Thing).filter_by(visible=True).order_by(Thing.id).all()
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
            db = shared.db_session_factory()
            try:
                data = json.loads(message)
                if isinstance(data, dict):
                    msg_type = data.get("type")
                    if msg_type:
                        if msg_type == "message":
                            await send_to_all(json.dumps(data))
                        elif msg_type == "command":
                            wslog.info("Command message: {}".format(message))
                            thing_id = data.get("id")
                            thing = db.query(Thing).get(thing_id)
                            if not thing:
                                wslog.warning("Thing {} is unknown".format(thing_id))
                                continue
                            if thing.type in ['switch', 'shelly']:
                                sw = db.query(Thing).get(thing_id)
                                val = data.get("value")
                                if val:
                                    sw.on()
                                else:
                                    sw.off()
                            else:
                                wslog.warning("Unsupported type for command: '{}'".format(thing.type))
                        elif msg_type == "last_seen":
                            things = db.query(Thing).all()
                            last_seen = {thing.id: thing.last_seen.isoformat() if thing.last_seen else None for thing in things}
                            msg = dict(type="last_seen", last_seen=last_seen)
                            await websocket.send(json.dumps(msg))
                        else:
                            wslog.warning("Unknown msg_type {}".format(msg_type))
                    else:
                        wslog.warning("Discarding message from {}: Missing \"type\" field".format(websocket.remote_address))
                else:
                    wslog.warning("Discarding message from {}: Not a JSON object: {}".format(websocket.remote_address, data))
            except json.JSONDecodeError as err:
                wslog.warning("Discarding message from {}: Can't decode as JSON ({})".format(websocket.remote_address, str(err)))
            db.close()
        else:
            wslog.info("Client {} disconnected".format(websocket.remote_address))
            connected_wss.remove(websocket)
            db.close()
    except websockets.exceptions.ConnectionClosed:
        connected_wss.remove(websocket)
        wslog.warning(f"Cleaning up stale connection: {websocket.remote_address}")
        if db:
            db.close()


def ws_thread(queue):
    wslog.info("Starting up")
    logging.getLogger("websockets.protocol").setLevel(logging.INFO)
    try:
        global ws_event_loop
        ws_event_loop = asyncio.new_event_loop()
        # ws_event_loop.set_debug(True)
        asyncio.set_event_loop(ws_event_loop)
        ws_server = websockets.serve(handle_ws_connection, getattr(config, "BIND_IP", "localhost"), 8765)
        ws_event_loop.run_until_complete(ws_server)
        ws_event_loop.run_forever()
        wslog.info("Shutting down")
    except Exception:
        wslog.exception("Uncaught Exception in ws_thread")
        

async def ws_shutdown():
    if connected_wss:
        await asyncio.wait([ws.close(reason="Shutting down") for ws in connected_wss])
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
        client.subscribe(list(zip(ts, [0]*len(ts))))


def on_mqtt_disconnect(client, userdata, rc):
    if rc == 0:
        mqttlog.info("Disconnected from MQTT broker")
    else:
        mqttlog.warning("Connection to MQTT broker lost. Reconnecting.")
        client.connect_async()


def on_mqtt_message(client, userdata, message):
    try:
        db = shared.db_session_factory()
        if message.topic.startswith("alive"):
            device_id = message.payload.decode("ascii")
            LastSeen.update_last_seen(db, device_id)
        else:
            node_type, vnode, stop = message.topic.split("/", maxsplit=3)
            if node_type == "shellies":
                device_id = node_type
                vnode_id = stop
                node_type = "shelly"
                # if vnode.startswith("shellybutton1"):
                #     node_type = "shellybutton"
            else:
                device_id, vnode_id = vnode.rsplit('-', maxsplit=1)
            thing = Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id)
            if not thing:
                return
            print("Thing {} {} sent new state".format(thing.type, thing.name))
            res = thing.process_status(db, message.payload.decode("ascii"))

            msg = dict(type="states", states=[db.query(State).get(res[2]).to_dict()])
            asyncio.run_coroutine_threadsafe(send_to_all(json.dumps(msg, cls=JsonEncoder)), ws_event_loop)
            rule_queue.put(res)
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
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message)


# noinspection PyUnusedLocal
def reload_sig(sig, frame):
    reload()


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

    grafana.start(bind_addr=config.BIND_IP, prefix="/grafana")
    print("Grafana API")

    rules.init_timers()
    # local timers
    try:
        local_rules.init_timers()
    except NameError:  # no module
        pass
    except AttributeError:  # no function
        pass

    try:
        while not request_shutdown:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    shutdown()


if __name__ == "__main__":
    main()
