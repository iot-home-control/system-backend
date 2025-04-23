# Home Control

Home Control is a no-cloud Internet of Things solution. 

Home Control has 3 Components
- the System Backend (this repository)
- the [Web Frontend](https://github.com/iot-home-control/frontend)
- the [Firmware](https://github.com/iot-home-control/firmware)

The System Backend connects to a Message Queue (MQTT) to get state messages of things (the T in IoT).
A received state is saved to a database and sent to all active web frontends via a web socket connection.
The Backend provides also a Grafana data source.
The system backend can collate the collected data into trends.

The System Backend has support for rules and timers written in Python.

## Documentation:
- [Installation guide](docs/install.md)
- [Rule writing guide](docs/rules.md)

## Development guide
- [How to run the test/development environment](docs/development.md)
- [Thing configuration](https://github.com/iot-home-control/firmware/README.md)

## Licensing
The Home-Control backend is licensed under the [GNU AGPL 3](LICENSE).
