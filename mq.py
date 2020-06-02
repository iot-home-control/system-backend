import paho.mqtt.client as mqttm
from typing import Optional
import logging

_mqtt: Optional[mqttm.Client] = None


def start(config, on_connect, on_disconnect, on_message):
    global _mqtt
    _mqtt = mqttm.Client()
    _mqtt.enable_logger(logging.getLogger("mqtt"))
    _mqtt.on_connect = on_connect
    _mqtt.on_disconnect = on_disconnect
    _mqtt.on_message = on_message
    _mqtt.username_pw_set(config.MQTT_USER,
                          config.MQTT_PASS)
    _mqtt.connect_async(config.MQTT_HOST)
    _mqtt.loop_start()


def stop():
    _mqtt.disconnect()
    _mqtt.loop_stop()


def publish(topic, payload):
    return _mqtt.publish(topic, payload)
