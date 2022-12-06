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

import logging
from typing import Optional

import paho.mqtt.client as mqttm

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


def subscribe(topic):
    return _mqtt.subscribe(topic)
