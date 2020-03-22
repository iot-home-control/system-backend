import mq
from models.database import Thing, DataType, LastSeen


class TemperatureSensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'temperature'
    }

    def get_data_type(self):
        return DataType.Float


class HumiditySensor(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'humidity'
    }

    def get_data_type(self):
        return DataType.Float


class LEDs(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'leds'
    }

    def get_data_type(self):
        return DataType.String


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


class Button(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'button'
    }

    def get_data_type(self):
        return DataType.Boolean


class Shelly(Thing):
    __mapper_args__ = {
        'polymorphic_identity': 'shelly'
    }

    def get_data_type(self):
        return DataType.Boolean

    def get_state_topic(self):
        return "shellies/{device_id}/relay/{vnode_id}".format(type=self.type, device_id=self.device_id,
                                                              vnode_id=self.vnode_id)

    def get_action_topic(self):
        return "shellies/{device_id}/relay/{vnode_id}/command".format(type=self.type, device_id=self.device_id,
                                                                      vnode_id=self.vnode_id)

    def process_status(self, db, state):
        last_state = self.last_state(db)
        LastSeen.update(db, self.device_id)
        if last_state.status_bool != (state.lower() in ["on", "yes", "true", "1"]):
            state = f"unknown,{state}"
            return super().process_status(db, state)
        return self.id, type(self), last_state.id


thing_type_table = {
    "switch": Switch,
    "temperature": TemperatureSensor,
    "humidity": HumiditySensor,
    "leds": LEDs,
    "button": Button,
    "shelly": Shelly,
}
