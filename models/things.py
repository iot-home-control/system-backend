from models.database import Thing, DataType


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
