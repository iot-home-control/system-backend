#!/usr/bin/env python3

import mq
from pprint import pprint
import shared
from models.database import Thing, State, LastSeen
import logging
import signal
import threading
import time
import os
import config
import datetime
from queue import Queue, Empty
import rules

logging.basicConfig(level=logging.INFO)
mqttlog = logging.getLogger("mqtt")
rulelog = logging.getLogger("rule")

request_shutdown = False
did_shutdown = False
rule_executor = None
db_session_factory = None
rule_queue = Queue()


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
                    revent = rules.RuleEvent(db.query(thing_class).get(thing_id), db.query(State).get(state_id))
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
            _, node_type, vnode, _ = message.topic.split("/", maxsplit=4)
            device_id, vnode_id = vnode.rsplit('-', maxsplit=1)
            thing = Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id)
            if not thing:
                return
            print("Thing {} sent new state".format(thing.name))
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
    print("Rule Execution")
    logging.shutdown()


def main():
    global rule_executor
    signal.signal(signal.SIGTERM, shutdown)

    print("Starting:", end=" ")
    mq.start(config, on_mqtt_connect, on_mqtt_disconnect, on_mqtt_message)
    print("MQTT", end=", ")

    rule_executor = threading.Thread(target=rule_executer_thread, args=(rule_queue,))
    rule_executor.start()
    print("Rule Execution")

    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass

    shutdown()


if __name__ == "__main__":
    main()
