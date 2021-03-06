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

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
from typing import Optional
from models.database import Thing, State, DataType, Trend
from shared import db_session_factory
import json
import dateutil.parser
from urllib.parse import urlparse, parse_qs
import os

_server: Optional[ThreadingHTTPServer] = None
_prefix: Optional[str] = ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("GET", self.path, self.client_address)
        if self.path == _prefix + "/":
            self.send_response(200)
            self.end_headers()
        elif self.path.startswith("/api/v1/config"):
            params = parse_qs(urlparse(self.path).query)
            device_id = params.get("device", [None])[0]
            if device_id:
                filename = os.path.join("../config/" + device_id + ".json")
                if os.path.exists(filename):
                    with open(filename, "rb") as f:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(f.read())
                        return

            self.send_error(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({}).encode())

        else:
            self.send_error(400)
            self.end_headers()

    def do_POST(self):
        print("POST", self.path, self.client_address)
        cl = int(self.headers.get("Content-Length"))
        if cl > 0:
            req_data = self.rfile.read(cl)
            req = json.loads(req_data)
        else:
            req = {}
        resp = {}

        if self.path == _prefix + "/search":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            db = db_session_factory()
            resp = [{"text": t.name + " (" + t.type.capitalize() + ")", "value": t.id} for t in db.query(Thing).order_by(Thing.id).all()]
            db.close()
        elif self.path == _prefix + "/query":
            targets = [t["target"] for t in req["targets"] if t.get("type") == "timeseries"]
            timerange = req["range"]
            range_start = dateutil.parser.parse(timerange["from"])
            range_stop = dateutil.parser.parse(timerange["to"])
            interval_ms = req["intervalMs"]
            max_data_points = req["maxDataPoints"]
            db = db_session_factory()

            resp = []
            for target in targets:
                if not target:
                    continue
                thing = db.query(Thing).get(target)
                if not thing:
                    continue
                display_name = thing.name + " (" + thing.type.capitalize() + ")"
                datatype = thing.get_data_type()
                datapoints = []
                trends = db.query(Trend).filter(Trend.start >= range_start, Trend.end <= range_stop, Trend.thing_id == thing.id).order_by(Trend.start)
                states = db.query(State).filter(State.when.between(range_start, range_stop), State.thing_id == thing.id).order_by(State.when)
                # print("Found", trends.count(), "trends for", thing.name, thing.type, thing.id, "between", range_start, "and", range_stop)
                for trend in trends.all():
                    when = round((trend.start + trend.interval/2).timestamp()*1000)
                    datapoints.append([trend.t_avg, when])
                for state in states.all():
                    when = round(state.when.timestamp()*1000)
                    if datatype == DataType.Float:
                        datapoints.append([state.status_float, when])
                    elif datatype == DataType.Boolean:
                        datapoints.append([state.status_bool, when])
                resp.append(dict(target=display_name, datapoints=datapoints))
            db.close()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        elif self.path == _prefix + "/annotations":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            resp = []
        else:
            self.send_error(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        self.wfile.write(json.dumps(resp).encode())


def start(bind_addr="", port=8000, prefix=None):
    global _server
    if prefix:
        global _prefix
        _prefix = prefix
    _server = ThreadingHTTPServer((bind_addr, port), Handler)
    _server_thread = threading.Thread(target=_server.serve_forever)
    _server_thread.daemon = True
    _server_thread.start()


def stop():
    _server.shutdown()
