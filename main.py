#!/usr/bin/env python3

import mq
import paho.mqtt.client as mqttm
from pprint import pprint
import shared
from models.database import Thing, State, LastSeen
from models.things import Shelly
import logging
import signal
import threading
import time
import os
import config
import datetime
from queue import Queue, Empty
import rules
import timer
import websockets
import asyncio
import json

logging.basicConfig(level=logging.DEBUG)
mqttlog = logging.getLogger("mqtt")
rulelog = logging.getLogger("rule")
timerlog = logging.getLogger("timer")
wslog = logging.getLogger("websocket")


request_shutdown = False
did_shutdown = False
rule_executor = None
timer_checker = None
websocket = None
db_session_factory = None
rule_queue = Queue()
ws_event_loop = None
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
    await asyncio.wait([ws.send(msg) for ws in connected_wss])


async def handle_ws_connection(websocket, path):
    wslog.info("Client {} connected".format(websocket.remote_address))
    connected_wss.add(websocket)
    async for message in websocket:
        try:
            data = json.loads(message)
            msg_type = data.get("type")
            if msg_type:
                if msg_type == "message":
                    await send_to_all(json.dumps(data))
            else:
                wslog.warning("Discarding message from {}: Missing \"type\" field".format(websocket.remote_address))
        except json.JSONDecodeError as err:
            wslog.warning("Discarding message from {}: Can't decode as JSON ({})".format(websocket.remote_address, str(err)))
    else:
        wslog.info("Client {} disconnected".format(websocket.remote_address))
        connected_wss.remove(websocket)


def ws_thread():
    wslog.info("Starting up")
    try:
        global ws_event_loop
        ws_event_loop = asyncio.new_event_loop()
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
        ts = [thing.get_state_topic() for thing in db.query(Thing).all()] + ["/alive"]
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
        if message.topic.startswith("/alive"):
            device_id = message.payload.decode("ascii")
            entry = db.query(LastSeen).filter_by(device_id=device_id).one_or_none()
            print("Thing {} is alive".format(device_id))
            if entry:
                entry.last_seen = datetime.datetime.utcnow()
                db.commit()
            else:
                entry = LastSeen()
                entry.device_id = device_id
                entry.last_seen = datetime.datetime.utcnow()
                db.add(entry)
                db.commit()
        else:
            start, node_type, vnode, stop = message.topic.split("/", maxsplit=4)
            if start == "shellies":
                device_id = node_type
                vnode_id = stop
                node_type = "shelly"
            else:
                device_id, vnode_id = vnode.rsplit('-', maxsplit=1)
            thing = Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id)
            if not thing:
                return
            print("Thing {} {} sent new state".format(thing.type, thing.name))
            res = thing.process_status(db, message.payload.decode("ascii"))
            rule_queue.put(res)
        db.close()
    except Exception:
        mqttlog.exception("Uncaught exception in on_mqtt_message")


def shutdown(*args):
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
    #ws_event_loop.call_soon_threadsafe(ws_shutdown)
    asyncio.run_coroutine_threadsafe(ws_shutdown(), ws_event_loop)
    websocket.join()
    print("WebSockets")
    logging.shutdown()


def main():
    global rule_executor
    global timer_checker
    global websocket
    signal.signal(signal.SIGTERM, shutdown)

    print("Starting:", end=" ")
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message)
    print("MQTT", end=", ")

    rule_executor = threading.Thread(target=rule_executer_thread, args=(rule_queue,))
    rule_executor.start()
    print("Rule Execution", end=", ")

    timer_checker = threading.Thread(target=timer_checker_thread)
    timer_checker.start()
    print("Timer Checker", end=", ")

    websocket = threading.Thread(target=ws_thread)
    websocket.start()
    print("WebSockets")

    rules.init_timers()

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    shutdown()


if __name__ == "__main__":
    main()
