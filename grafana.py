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

import datetime
import itertools
import json
import math
import os
import threading
import time
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

            def round_dt_to_seconds(dt: datetime.datetime) -> datetime.datetime:
                if dt.microsecond < 50000:
                    return dt.replace(microsecond=0)
                else:
                    return dt.replace(microsecond=0) + datetime.timedelta(seconds=1)

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
                    # print("Found", trends.count(), "trends for", thing.name, thing.type, thing.id, "between", range_start, "and", range_stop)
                    for trend in trends.all():
                        when = round((trend.start + trend.interval/2).timestamp()*1000)
                        if trend.t_avg is None or math.isnan(trend.t_avg):
                            continue
                        datapoints.append([trend.t_avg, when])
                    for when, value in states:
                        if value is None:
                            continue
                        if datatype == DataType.Float and not math.isnan(value):
                            datapoints.append([value, when])
                        elif datatype == DataType.Boolean:
                            datapoints.append([value, when])

                    if len(datapoints) == 0:
                        print("no dp")
                        resp.append(dict(target=display_name, datapoints=datapoints))


                    #interval_points = [range_start + datetime.timedelta(milliseconds=interval_ms * i) for i in
                    #                   range(round((range_stop-range_start).total_seconds()*1000 / interval_ms))]
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

                        assert datapoints[dp_index][1] > current_interval, f'Constraints failed\n{current_interval=},\n{datapoints[dp_index][1]=}\n{dp_index=}/{len(datapoints) - 1}, {interval_index=}/{len(interval_points) - 1}'

                        dp_left = datapoints[dp_index - 1]
                        dp_right = datapoints[dp_index]

                        if dp_right[1] > interval_points[interval_index][2]:
                            # If the point we looked at is outside the interval (no points between the one before the
                            # interval and this one after it), look at the next interval.
                            interval_index += 1
                            continue

                        assert dp_left[1] < current_interval <= dp_right[1], f'Constraints failed\n{dp_left[1]=},\n{current_interval=},\n{dp_right[1]=}'
                        timediff = dp_right[1] - dp_left[1]
                        assert timediff.total_seconds() > 0
                        f = (current_interval - dp_left[1]) / timediff
                        assert f >= 0, f'{current_interval=} {dp_left[1]=} {timediff=}'
                        v = dp_left[0] + (dp_right[0] - dp_left[0]) * f
                        resampled.append([v, round(current_interval.timestamp() * 1000)])

                        interval_index += 1

                    """
                    interval_index = 0
                    start = time.time()
                    print(start)

                    for left_dp, right_dp in itertools.pairwise(datapoints):

                        for interval in range(interval_index, len(interval_points)):
                            current_interval = interval_points[interval]
                            #x = time.time()
                            if current_interval[0] <= left_dp[1]:
                                if left_dp[1] < current_interval[1] and current_interval[1] <= right_dp[1] < current_interval[2]:
                                    #print("y", time.time() -x )
                                    timediff = right_dp[1] - left_dp[1]
                                    #assert timediff.total_seconds() > 0
                                    f = (current_interval[1] - left_dp[1]) / timediff
                                    #assert f >= 0, f'{current_interval=} {left_dp[1]=} {timediff=}'
                                    v = left_dp[0] + (right_dp[0] - left_dp[0]) * f
                                    resampled.append([v, round(current_interval[1].timestamp() * 1000)])
                                    #print(interval-interval_index)
                                    interval_index = interval
                                    break
                            else:
                                interval_index = interval
                                #print("n", time.time() - x)
                    print(f"needed: {time.time()-start} for {len(datapoints)}")
                    """
                    """
                            if interval < len(interval_points) - 1 and right_dp[1] >= interval_points[interval + 1]:

                            if left_dp[1] < interval_points[interval] <= right_dp[1]:
                                interval_index = interval
                                continue

                                interval_index = interval
                                break
                        current_interval = interval_points[interval_index]
                        assert left_dp[1] < current_interval <= right_dp[1], f'{left_dp[1]=} {current_interval=}, {right_dp[1]=}'

                        timediff = right_dp[1] - left_dp[1]
                        assert timediff.total_seconds() > 0
                        f = (current_interval - left_dp[1]) / timediff
                        assert f >= 0, f'{current_interval=} {left_dp[1]=} {timediff=}'
                        v = left_dp[0] + (right_dp[0] - left_dp[0]) * f
                        resampled.append([v, round(current_interval.timestamp() * 1000)])
                        """
                    """
                    interval_index = 1
                    interval_td = datetime.timedelta(milliseconds=interval_ms)

                    dp_index = 0
                    for index in range(0, len(interval_points)):
                        items = []
                        dp = datapoints[dp_index]
                        new_dp = datapoints[dp_index]
                        while index < len(interval_points)-1 and new_dp[1] < interval_points[index+1]:
                            dp_index += 1
                            if dp_index >= len(datapoints):
                                break
                            dp = new_dp
                            new_dp = datapoints[dp_index]
                            if new_dp[1] < interval_points[index]:
                                continue
                        if index >= len(interval_points)-1 or dp[1] >= interval_points[index+1]:
                            continue
                        assert dp != new_dp
                        # linear intepolation
                        assert dp[1] <= interval_points[index+1] <= new_dp[1], f'{index=} {dp[1]=}, {interval_points[index+1]=} {new_dp[1]=}'

                        timediff = new_dp[1] - dp[1]
                        f = (interval_points[index+1] - dp[1]) / timediff
                        assert f >= 0
                        v = dp[0] + (new_dp[0] - dp[0]) * f
                        resampled.append([v, round(interval_points[index+1].timestamp()*1000)])
                        """

                    """
                    for index in range(1, len(datapoints)):  # since we already added the first point to resampled
                    dp = datapoints[index]
                    if dp[1] < interval_points[interval_index]:
                        continue
                
                    while interval_index < len(interval_points) - 1 and dp[1] > interval_points[interval_index] + interval_td:
                        interval_index += 1
                
                    timediff = dp[1] - datapoints[index - 1][1]
                    if timediff.total_seconds() == 0:
                        resampled.append([value, round(interval_points[interval_index].timestamp() * 1000)])
                        continue
                    f = (interval_points[interval_index] - datapoints[index - 1][1]) / timediff
                    value = datapoints[index - 1][0] + (dp[0] - datapoints[index - 1][0]) * f
                    if value < 0:
                        print(timediff, f, value, datapoints[index - 1][0], dp[0], datapoints[index - 1][1],
                              interval_points[interval_index])
                    resampled.append([value, round(interval_points[interval_index].timestamp() * 1000)])
                    """

                    # resampled.append([dp[0], round(interval_points[interval_index].timestamp()*1000)])

                    print(interval_ms, len(resampled), "<-", len(datapoints), max_data_points)
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
