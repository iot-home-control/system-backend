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

import rules
import shared
import timer
from rules import rule, Thing
from models.database import RuleState


@rule("Button Rule", Thing("shellybutton", device_id="shellybutton1-DEVICE_ID"))
def button_rule(event):
    # Create a database connection
    with shared.db_session_factory() as db:
        if event.state == "S":
            # Get RuleState of rule with "Rule Identifier".
            rule_state = db.query(RuleState).get("Rule Identifier")
            # Toggle rule state
            rule_state.enabled = not rule_state.enabled
            db.commit()
        else:
            # Get all things of type "switch" and "shelly". Thing.resolve returns all things matching the Thing descriptor.
            switches = Thing("switch").resolve(db)
            shellies = Thing("shelly").resolve(db)
            # Iterate over all found things and switch them off.
            for switch in switches + shellies:
                switch.off()


@rule("Rule Identifier", Thing("temperature", name="Example"))
def rule_function_name(event):
    # This is a dummy rule used to demonstrate that rules can be enabled/disabled
    print("This rule was triggered by", event)


@rule("Timer Identifier")
def timer_function_name(event):
    with shared.db_session_factory() as db:
        switch = Thing("switch", name="Example Switch").resolve(db)[0]
        if switch.last_state(db).status_bool:
            switch.off()
        else:
            switch.on()


def init_timers():
    timer.add_timer("Example timer name", timer_function_name, cron="*/5 8-17 * * Mon-Fri")
