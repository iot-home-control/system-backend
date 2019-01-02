from models.database import Thing, DataType
import mq

class TemperatureSensor(Thing):
    def get_data_type(self):
        return DataType.Float


class HumiditySensor(Thing):
    def get_data_type(self):
        return DataType.Float


class LEDs(Thing):
    def get_data_type(self):
        return DataType.String


class Switch(Thing):
    def get_data_type(self):
        return DataType.Boolean

    def on(self):
        mq.publish(self.get_action_topic(), "on")

    def off(self):
        mq.publish(self.get_action_topic(), "off")


class Button(Thing):
    def get_data_type(self):
        return DataType.Boolean


thing_type_table = {
    "switch": Switch,
    "temperature": TemperatureSensor,
    "humidity": HumiditySensor,
    "leds": LEDs,
    "button": Button,
}
