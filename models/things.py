# SPDX-License-Identifier: AGPL-3.0-or-later
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

import json
from typing import List

import mq
from models.database import Thing, DataType, DeviceInfo


class TemperatureSensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'temperature'
    }

    def get_data_type(self):
        return DataType.Float

    @classmethod
    def display_name(cls):
        return 'Temperature Sensor'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'temperature/+/state',


class HumiditySensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'humidity'
    }

    def get_data_type(self):
        return DataType.Float

    @classmethod
    def display_name(cls):
        return 'Humidity Sensor'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'humidity/+/state',


class PressureSensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'pressure'
    }

    def get_data_type(self):
        return DataType.Float

    @classmethod
    def display_name(cls):
        return 'Pressure Sensor'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'pressure/+/state',


class SoilMoistureSensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'soilmoisture'
    }

    def get_data_type(self):
        return DataType.Float

    @classmethod
    def display_name(cls):
        return 'Soil Moisture Sensor'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'soilmoisture/+/state',


class LEDs(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'leds'
    }

    def get_data_type(self):
        return DataType.String

    @classmethod
    def display_name(cls):
        return None


class Switch(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'switch'
    }

    def get_data_type(self):
        return DataType.Boolean

    def on(self):
        mq.publish(self.get_action_topic(), "on")

    def off(self):
        mq.publish(self.get_action_topic(), "off")

    @classmethod
    def display_name(cls):
        return 'Switch'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'switch/+/state',


class Button(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'button'
    }

    def get_data_type(self):
        return DataType.Boolean

    @classmethod
    def display_name(cls):
        return None


class Shelly(Switch):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly'
    }

    def get_state_topic(self):
        return "shellies/{device_id}/relay/{vnode_id}".format(type=self.type, device_id=self.device_id,
                                                              vnode_id=self.vnode_id)

    def get_action_topic(self):
        return "shellies/{device_id}/relay/{vnode_id}/command".format(type=self.type, device_id=self.device_id,
                                                                      vnode_id=self.vnode_id)

    def process_status(self, db, state, data):
        last_state = self.last_state(db)
        DeviceInfo.update_device_info(db, self.device_id)
        if last_state is None or last_state.status_bool != (state.lower() in ["on", "yes", "true", "1"]):
            state = f"unknown,{state}"
            return super().process_status(db, state, data)
        return self.id, type(self), "state", last_state.id

    @classmethod
    def display_name(cls):
        return 'Shelly'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/relay/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / relay / vnode
        node_type = 'shelly'
        device_id = topic[1]
        vnode_id = topic[3]
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyTemperature(TemperatureSensor):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly_temperature'
    }

    def get_state_topic(self):
        return "shellies/{device_id}/ext_temperature/{vnode_id}".format(type=self.type, device_id=self.device_id,
                                                                        vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        state = f"unknown,{state}"
        return super().process_status(db, state, data)

    @classmethod
    def display_name(cls):
        return 'Shelly Temperature'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/ext_temperature/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / ext_temperature / vnode
        node_type = 'shelly_temperature'
        device_id = topic[1]
        vnode_id = topic[3]
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyHumidity(HumiditySensor):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly_humidity'
    }

    def get_state_topic(self):
        return "shellies/{device_id}/ext_humidity/{vnode_id}".format(type=self.type, device_id=self.device_id,
                                                                     vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        state = f"unknown,{state}"
        return super().process_status(db, state, data)

    @classmethod
    def display_name(cls):
        return 'Shelly Humidity'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/ext_humidity/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / ext_humidity / vnode
        node_type = 'shelly_humidity'
        device_id = topic[1]
        vnode_id = topic[3]
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyPower(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly_power'
    }

    def get_data_type(self):
        return DataType.Float

    def get_state_topic(self):
        return "shellies/{device_id}/emeter/{vnode_id}/power".format(type=self.type, device_id=self.device_id,
                                                                     vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        state = f"unknown,{state}"
        return super().process_status(db, state, data)

    @classmethod
    def display_name(cls):
        return 'Shelly Power'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/emeter/+/power', 'shellies/+/relay/+/power',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / emeter / vnode / function
        node_type = 'shelly_power'
        device_id = topic[1]
        vnode_id = topic[3]
        function = topic[4]  # noqa: unused

        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyEnergy(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly_energy'
    }

    def get_data_type(self):
        return DataType.Float

    def get_state_topic(self):
        return "shellies/{device_id}/emeter/{vnode_id}/total".format(type=self.type, device_id=self.device_id,
                                                                     vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        if data.get("is_shellyplug", False):
            # Shelly energy meters report in Wh, Shelly Plugs report in Watt-minutes, so divide by 60 to also get Wh.
            state = float(state) / 60.0
        state = f"unknown,{state}"
        return super().process_status(db, state, data)

    @classmethod
    def display_name(cls):
        return 'Shelly Energy'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/emeter/+/total', 'shellies/+/relay/+/energy',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / emeter / vnode / function
        # shellies / node / relay / vnode / energy
        node_type = 'shelly_energy'
        device_id = topic[1]
        vnode_id = topic[3]
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), dict(is_shellyplug="shellyplug" in device_id)


class ESP32Smartmeter(Thing):
    __abstract__ = True

    def get_data_type(self):
        return DataType.Float

    def get_state_topic(self):
        return 'smartmeter/{device_id}/{subtype}/{vnode_id}'.format(device_id=self.device_id, subtype=self.subtype,
                                                                    vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id, threshold_s=60)
        state = f"local,{state}"
        return super().process_status(db, state, data)


class ESP32SmartmeterPower(ESP32Smartmeter):
    __mapper_args__ = {
        'polymorphic_identity': 'esp32_smartmeter_power'
    }

    subtype = 'power'

    @classmethod
    def display_name(cls):
        return 'ESP32 Power'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'smartmeter/+/power/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # smartmeter / device_id / subtype / vnode
        node_type = 'esp32_smartmeter_power'
        device_id = topic[1]
        subtype = topic[2]  # noqa: unused
        vnode_id = topic[3]

        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ESP32SmartmeterEnergy(ESP32Smartmeter):
    __mapper_args__ = {
        'polymorphic_identity': 'esp32_smartmeter_energy'
    }

    subtype = 'reading'

    @classmethod
    def display_name(cls):
        return 'ESP32 Energy'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'smartmeter/+/reading/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # smartmeter / device_id / subtype / vnode
        node_type = 'esp32_smartmeter_energy'
        device_id = topic[1]
        subtype = topic[2]  # noqa: unused
        vnode_id = topic[3]

        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyTRV(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'shellytrv'
    }

    def get_data_type(self):
        return DataType.Float

    def get_state_topic(self):
        return "shellies/{device_id}/info".format(type=self.type, device_id=self.device_id, vnode_id=self.vnode_id)

    def get_base_topic(self):
        return "shellies/{device_id}/thermostat/{vnode_id}/command".format(type=self.type,
                                                                           device_id=self.device_id,
                                                                           vnode_id=self.vnode_id)

    def get_action_topic(self):
        return f"{self.get_base_topic()}/target_t"

    def send_external_temperature(self, value):
        mq.publish(f"{self.get_base_topic()}/ext_t", value)

    def send_value(self, value):
        # Todo: clamp values if needed
        mq.publish(self.get_action_topic(), value)

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        try:
            data = json.loads(state)
            state = data.get("thermostats")[self.vnode_id].get("target_t").get("value")
        except (json.JSONDecodeError, IndexError):
            state = None
        return super().process_status(db, f"unknown, {state}", data)

    @classmethod
    def display_name(cls):
        return 'Shelly TRV'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/info',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / info
        node_type = 'shellytrv'
        device_id = topic[1]
        vnode_id = 0
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyButton(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'shellybutton'
    }

    def get_data_type(self):
        return DataType.Nothing

    def get_state_topic(self):
        return "shellies/{device_id}/input_event/{vnode_id}".format(type=self.type, device_id=self.device_id,
                                                                    vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        try:
            data = json.loads(state)
        except json.JSONDecodeError:
            ...
        event = data.get("event")  # S, SS, SSS, L
        return self.id, type(self), "event", event

    @classmethod
    def display_name(cls):
        return 'Shelly Button'

    @staticmethod
    def get_mqtt_subscriptions():
        return 'shellies/+/input_event/+',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellies / node / input_event / vnode
        node_type = 'shellybutton'
        device_id = topic[1]
        vnode_id = topic[3]
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class ShellyPlus(Switch):
    __mapper_args__ = {
        'polymorphic_identity': 'shellyplus'
    }

    """
    > shellyplus2pm-a8032ab66ae0/rpc '{"id":2, "src": "test", "method": "Switch.Set", "params":{"id":1 "on":true}}'
    < shellyplus2pm-a8032ab66ae0/status/switch:0 {
        "id":0,
        "source":"WS_in",
        "output":false,
        "apower":0.0,
        "voltage":232.3,
        "current":0.000,
        "pf":0.00,
        "aenergy":{"total":100.545,"by_minute":[0.000,0.000,0.000],"minute_ts":1669572158},
        "temperature":{"tC":50.4, "tF":122.7}
    }
    """

    @staticmethod
    def get_mqtt_subscriptions():
        return '+/status/+',

    def get_action_topic(self):
        return "{device_id}/rpc".format(device_id=self.device_id)

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        try:
            data = json.loads(state)
        except json.JSONDecodeError:
            data = {}

        state = data.get("output")
        return super().process_status(db, f"{'local' if data.get('source') == 'switch' else 'mqtt'},{state}", data)

    def on(self):
        payload = {"id": 42, "src": "home-control", "method": "Switch.Set",
                   "params": {"id": self.vnode_id, "on": True}}
        mq.publish(self.get_action_topic(), json.dumps(payload))

    def off(self):
        payload = {"id": 42, "src": "home-control", "method": "Switch.Set",
                   "params": {"id": self.vnode_id, "on": False}}
        mq.publish(self.get_action_topic(), json.dumps(payload))

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # shellplus<subtype>-<id> / status / <part>:<vnode>
        node_type = 'shellyplus'
        device_id = topic[0]
        vnode_id = int(topic[-1].split(':')[-1])
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


class FrischluftWorksCO2Sensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'frischluftworks-co2'
    }

    def get_data_type(self):
        return DataType.Float

    def get_state_topic(self):
        return "FRISCHLUFT/{device_id}/values/raw/co2".format(type=self.type, device_id=self.device_id,
                                                              vnode_id=self.vnode_id)

    def get_action_topic(self):
        return None

    def process_status(self, db, state, data):
        DeviceInfo.update_device_info(db, self.device_id)
        state = f"local,{state}"
        return super().process_status(db, state, data)

    @classmethod
    def display_name(cls):
        return "frischluft.works CO₂ Sensor"

    @staticmethod
    def get_mqtt_subscriptions():
        return 'FRISCHLUFT/+/values/raw/co2',

    @staticmethod
    def get_by_mqtt_topic(db, topic: List[str]):
        # FRISCHLUFT / node / values / raw / co2
        node_type = 'frischluftworks-co2'
        device_id = topic[1]
        vnode_id = 0
        return Thing.get_by_type_and_device_id(db, node_type, device_id, vnode_id), None


thing_type_table = {
    "switch": Switch,
    "temperature": TemperatureSensor,
    "humidity": HumiditySensor,
    "soilmoisture": SoilMoistureSensor,
    "leds": LEDs,
    "button": Button,
    "shelly": Shelly,
    "pressure": PressureSensor,
    "shellybutton": ShellyButton,
    "shellytrv": ShellyTRV,
    "shelly_power": ShellyPower,
    "shelly_energy": ShellyEnergy,
    "shelly_temperature": ShellyTemperature,
    "shelly_humidity": ShellyHumidity,
    "shellyplus": ShellyPlus,
    "frischluftworks-co2": FrischluftWorksCO2Sensor,
    "esp32_smartmeter_power": ESP32SmartmeterPower,
    "esp32_smartmeter_energy": ESP32SmartmeterEnergy,
}
