#!/usr/bin/env python3

from pprint import pprint

from shared import db_engine
from models.database import Thing, State, LastSeen
import logging
import paho.mqtt.client as mqttm
import signal
import threading
import time
import os
from config import *
from sqlalchemy.orm import sessionmaker
import datetime
from queue import Queue, Empty

logging.basicConfig(level=logging.INFO)
mqttlog = logging.getLogger("mqtt")
rulelog = logging.getLogger("rule")

request_shutdown = False
did_shutdown = False
mqtt = None
rule_executor = None
db_session = None
rule_queue = Queue()


def rule_executer_thread(queue):
    global request_shutdown
    import rules
    rulelog.info("Staring up")
    while not request_shutdown:
        while True:
            try:
                event = queue.get_nowait()
                if not event:
                    break
                thing, state = event
                for rule in rules.triggers.get(thing, []):
                    try:
                        rule()
                    except Exception:
                        rulelog.exception("Error while executing rule {}".format(rules.all_rules[rule]))
                queue.task_done()
            except Empty:
                break

        time.sleep(0.2)
    rulelog.info("Shutting down")


def on_mqtt_connect(client, userdata, flags, rc):
    if rc != 0:
        mqttlog.error("Can't connect to MQTT broker: %s",
                      mqttm.connack_string(rc))
        shutdown()
        return
    else:
        mqttlog.info("Connected to MQTT broker. Subscribing topics.")
        ts = [thing.get_state_topic() for thing in db_session.query(Thing).all()]
        client.subscribe(list(zip(ts, [0]*len(ts))))


def on_mqtt_disconnect(client, userdata, rc):
    if rc == 0:
        mqttlog.info("Disconnected from MQTT broker")
    else:
        mqttlog.warning("Connection to MQTT broker lost. Reconnecting.")
        client.connect_async()


def on_mqtt_message(client, userdata, message):
    _, node_type, vnode, _ = message.topic.split("/", maxsplit=4)
    device_id, vnode_id = vnode.rsplit('-', maxsplit=1)

    thing = Thing.get_by_type_and_device_id(db_session, node_type, device_id, vnode_id)
    if not thing:
        return
    print("Thing {} sent new state".format(thing.name))
    rule_queue.put(thing.process_status(db_session, message.payload.decode("ascii")))


def shutdown(*args):
    global did_shutdown
    global mqtt
    global rule_executor
    global request_shutdown
    if did_shutdown:
        return
    did_shutdown = True
    print("Shutting down:", end=" ")
    mqtt.disconnect()
    mqtt.loop_stop()
    print("MQTT", end=", ")

    request_shutdown = True
    rule_executor.join()
    print("Rule Execution")
    logging.shutdown()


def main():
    db_session_maker = sessionmaker(bind=db_engine)
    global db_session
    db_session = db_session_maker()
    global mqtt
    global rule_executor
    global rule_queue
    signal.signal(signal.SIGTERM, shutdown)

    print("Starting:", end=" ")
    mqtt = mqttm.Client()
    mqtt.on_connect = on_mqtt_connect
    mqtt.on_disconnect = on_mqtt_disconnect
    mqtt.on_message = on_mqtt_message
    mqtt.username_pw_set(MQTT_USER,
                         MQTT_PASS)
    mqtt.connect_async(MQTT_HOST)
    mqtt.loop_start()
    print("MQTT", end=", ")

    rule_executor = threading.Thread(target=rule_executer_thread, args=(rule_queue,))
    rule_executor.start()
    print("Rule Execution")

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
#    finally:

    shutdown()


if __name__ == "__main__":
    main()


