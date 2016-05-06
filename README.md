# pf-ispcap

Monitor pfsense bandwidth utilization with respect to ISP data caps.

Status
------

Very early development stage.

Why
---

Nothing out there does quite what I want.  To compare with ISP usage meters,
raw numbers need to be captured.  Even if you don't have a cap, it's nice to
have some idea how much is used as measured by your own gear.

Comcast 1TB cap is really 1000GB.  It's not bad, but it's still a cap.

What
----

Aggregate by hour, day, month and generate textual reports.

Capture the following aggregates but maybe only report on total utilization for starters.

* Total utilization
* In/Out/ipv6/ipv4/Passed/Blocked

I'm thinking it might be nice to periodically generate reports to /tmp and possibly
link to it from the web UI.

To keep stored records to a minimum, hourly only for the last two days by default, daily
for the last week by default, and monthly for the past 24 months by default.
These should all be configurable.

How
---

Storage layer will probably be sqlite3 and/or json.

Uses pfsense configuration to fetch wan interface and for basic settings
such as day of the month when the ISP meter is reset.

I'm testing against the version on my router -- 2.3.
