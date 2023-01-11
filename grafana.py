# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2021-2023 The Home Control Authors
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

import datetime
import json
import math
import os
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional
from urllib.parse import urlparse, parse_qs

import dateutil.parser
import sqlalchemy as sa

from models.database import Thing, State, DataType, Trend
from shared import db_session_factory

_server: Optional[ThreadingHTTPServer] = None
_prefix: Optional[str] = ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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

            with db_session_factory() as db:
                rows = db.execute(sa.select(Thing.id, Thing.name, Thing.type).order_by(Thing.id))
                resp = [{"text": n + " (" + t.capitalize() + ")", "value": i} for i, n, t in rows]
        elif self.path == _prefix + "/query":
            targets = [t["target"] for t in req["targets"] if t.get("type", "timeseries") == "timeseries"]
            timerange = req["range"]
            range_start = dateutil.parser.parse(timerange["from"]).replace(microsecond=0)
            range_stop = dateutil.parser.parse(timerange["to"]).replace(microsecond=0)
            interval_ms = req["intervalMs"]
            max_data_points = req["maxDataPoints"]

            data_column_map = {
                DataType.Float: State.status_float,
                DataType.Boolean: State.status_bool,
            }

            with db_session_factory() as db:
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
                    trends_query = sa.select(Trend) \
                                     .where(Trend.start >= range_start, Trend.end <= range_stop,
                                            Trend.thing_id == thing.id) \
                                     .order_by(Trend.start)

                    if max_data_points == 1:
                        trends_query = trends_query.limit(1)

                    trends = db.execute(trends_query).scalars()

                    states_query = sa.select(State.when, data_column_map[datatype]) \
                                     .where(State.thing_id == thing.id, State.when.between(range_start, range_stop)) \
                                     .order_by(State.when)

                    if max_data_points == 1:
                        states_query = states_query.limit(1)

                    states = db.execute(states_query)
                    for trend in trends.all():
                        if trend.t_avg is None or math.isnan(trend.t_avg):
                            continue
                        datapoints.append([trend.t_avg, trend.start + trend.interval/2])
                    for when, value in states:
                        if value is None:
                            continue
                        if datatype == DataType.Float and not math.isnan(value):
                            datapoints.append([value, when])
                        elif datatype == DataType.Boolean:
                            datapoints.append([value, when])

                    if len(datapoints) == 0:
                        resp.append(dict(target=display_name, datapoints=[]))

                    interval_points = []

                    duration_td = datetime.timedelta(milliseconds=interval_ms)
                    i_prev = range_start - duration_td
                    i_current = range_start
                    i_next = range_start + duration_td

                    for i in range(round((range_stop-range_start).total_seconds()*1000 / interval_ms)):
                        interval_points.append((i_prev, i_current, i_next))
                        i_prev, i_current, i_next = i_current, i_next, i_next + duration_td

                    resampled = []

                    interval_index = 0
                    dp_index = 0

                    while interval_index < len(interval_points) and dp_index < len(datapoints):
                        current_interval = interval_points[interval_index][1]

                        # Go forward (while possible) until the dp just crossed the interval point
                        while dp_index < len(datapoints) - 1 and datapoints[dp_index][1] < current_interval:
                            dp_index += 1

                        if dp_index == 0:
                            # If the first point already is after the interval, try the next interval.
                            interval_index += 1
                            continue
                        elif dp_index == len(datapoints) - 1 and datapoints[dp_index][1] < current_interval:
                            # If we're on the last point and the interval doesn't match, try the next interval.
                            interval_index += 1
                            continue

                        # assert datapoints[dp_index][1] > current_interval,\
                        #     f'Constraints failed\n{current_interval=},\n' \
                        #     f'{datapoints[dp_index][1]=}\n' \
                        #     f'{dp_index=}/{len(datapoints) - 1}, {interval_index=}/{len(interval_points) - 1}'

                        dp_left = datapoints[dp_index - 1]
                        dp_right = datapoints[dp_index]

                        if dp_right[1] > interval_points[interval_index][2]:
                            # If the point we looked at is outside the interval (no points between the one before the
                            # interval and this one after it), look at the next interval.
                            interval_index += 1
                            continue

                        # assert dp_left[1] < current_interval <= dp_right[1],\
                        #     'Constraints failed\n{dp_left[1]=},\n{current_interval=},\n{dp_right[1]=}'
                        timediff = dp_right[1] - dp_left[1]
                        # assert timediff.total_seconds() > 0
                        f = (current_interval - dp_left[1]) / timediff
                        # assert f >= 0, f'{current_interval=} {dp_left[1]=} {timediff=}'
                        v = dp_left[0] + (dp_right[0] - dp_left[0]) * f
                        resampled.append([v, round(current_interval.timestamp() * 1000)])

                        interval_index += 1

                    resp.append(dict(target=display_name, datapoints=resampled))

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
