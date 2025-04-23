# MQTT Structure 

Home Control supports many kinds of devices.
The devices which uses the Home Control Firmware use the following scheme for mqtt communication.
For other things consult documentation of manufacturer.


## Thing topics:
### Base topic
All Home-Control firmware devices use topics of the following structure `<type>/<device_id>-<vnode_id>/`.
For a list of supported device `<type>` values see the keys of `thing_type_table` in `models/things.py`.
The `<device_id>` is an arbitrary string identifying the device. The `<vnode_id>` is the numeric sub-device-identifier (staring at 0).
Values other than 0 are used if there are multiple sensors/actors of the same `<type>` on a single device, e.g. a sensor node with multiple temperature sensors connected.

Example base topics:
- `temperature/esp8266-012345-0`
- `temperature/esp8266-012345-1`
- `pressure/esp8266-012345-1`


### State topic:
The state topic `<base_topic>/state` payload is ASCII text of the form `<event_source>,<value>`.
`<event_source>` is either `local` or `mqtt` indicating the source of the state trigger.
The content of `<value>` is dependent on the device type, supported are boolean, numeric (stored as a floating point number), and string.

Example state messages:
- `switch/esp8266-234567-0/state mqtt,on`
- `switch/esp8266-234567-0/state mqtt,off`


### Action topic:
The action topic `<base_topic>/action` is used to control/trigger actions on devices. The format is device specific.

Example action messages:
- `switch/esp8266-234567-0/action on`
- `switch/esp8266-234567-0/action off`

## Device alive detection and house-keeping
The `alive` topic is used to populate the `device_information` table in the database.
The table contains the `device_id`, a `last_seen` value, and other house-keeping data.
The `last_seen` field is synthesized by the backend with the timestamp the message was processed at.
The `alive` topic supports two payload schemes.

1. Simple device announcement (legacy): The device just sends its device_id as an ASCII string.
2. Structured device announcement: The device sends a JSON payload containing additional information  
   - `device_id` ID of the device
   - `ip_addr` current IP address
   - `firmware_version` is current device firmware version 
   - `is_updatable` indicates whether a firmware update is available
   Any other fields in the JSON will be put into the `data` field of the entry for that device.

Example alive messages:
- Structured: `alive {"device_id":"esp8266-01234","local_ip":"192.168.178.108","build_date":"2025-01-16T10:33Z","git_version":"ebe1dbc","update_available":null}`
- Simple (legacy): `alive esp8266-234567`
