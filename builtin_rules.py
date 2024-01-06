import datetime

import rules
import timer
import mq


@timer.timer
@rules.rule("Request Shelly announces")
def _request_shelly_announces():
    mq.publish("shellies/command", "announce")


def init_timers():
    timer.add_timer("Request Shelly announces", _request_shelly_announces, interval=datetime.timedelta(hours=24))
