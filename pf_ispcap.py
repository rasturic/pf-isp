#!/usr/local/bin/python2

# Count all IN bytes,all passed OUT bytes in various ways

# Make daily, weekly, and monthly usage reports

import os
import syslog
import subprocess
import xml.etree.ElementTree as et
import time
import json
from time import sleep


class Conf(object):
    """
    Class for configuration data
    """
    system_config_filename = "/conf/config.xml"

    # overridden by configuration file
    wan_if = "igb0"

    # fields we look for in <pf-ispcap> section
    settings_keys = ('reset_day', 'conversion', 'interval')

    # reset_day. day of month when usage meter resets
    # conversion factor.  si: 1000. iec: 1024.  Most use si now.
    # interval.  read interface values every N seconds
    # isp_cap.  isp bandwidth cap in gigabytes
    # These defaults are overridden in the pfsense configuration <pf-ispcap> section

    settings = {
        'reset_day': 1,
        'conversion': 1000,
        'interval': 60,
        'isp_cap': 1000
    }

    @classmethod
    def read_conf(cls, conf_fd=None):
        if not conf_fd:
            if not os.path.exists(cls.system_config_filename):
                syslog.syslog("System configuration not found")
                return
            conf_fd = open(cls.system_config_filename)

        data = conf_fd.read()
        tree = et.fromstring(data)
        wan_if = tree.find("interfaces/wan/if")
        if wan_if is not None:
            cls.wan_if = wan_if.text
        pf_isp = tree.find("pf-ispcap")
        if pf_isp is not None:
            for setting in cls.settings_keys:
                value = pf_isp.find(setting)
                if value is not None:
                    if value.text.isdigit():
                        cls.settings[setting] = int(value.text)
                    else:
                        cls.settings[setting] = value.text


class Interface(object):
    counted = ('In4/Pass','In4/Block','Out4/Pass',
               'In6/Pass', 'In6/Block', 'Out6/Pass')
    counted_sum = ('All', 'In', 'Out', '6', '4', 'Pass', 'Block')


class IntervalDiff(Interface):
    """
    Compare PfCtl objects
    """

    def __init__(self, previous, current):
        self.previous, self.current = previous, current
        self.diff = {}
        self._calc_diff()
        self.prev = {}
        self.prev['values'] = previous.values.copy()
        self.prev['values_sum'] = previous.values_sum.copy()

    def _calc_diff(self):
        # undecided how to handle rollover, reboot or cleared events.  not implemented yet.
        self.diff['seconds'] = self.current.timestamp - self.previous.timestamp

        # for testing purposes
        if self.diff['seconds'] == 0:
            self.diff['seconds'] = 1

        for key in self.counted:
            self.diff[key] = self.current.values[key] - self.previous.values[key]
        for key in self.counted_sum:
            self.diff[key] =  self.current.values_sum[key] - self.previous.values_sum[key]
        self.diff['mbs'] = (self.diff['All'] * 8 / 1000000 ) / self.diff['seconds']
        self.diff['begin'], self.diff['end'] = self.previous.timestamp, self.current.timestamp

    def __str__(self):
        return repr(self.diff)

    def __repr__(self):
        return json.dumps(self.diff, indent=2)

class PfCtl(Interface):
    """
    Class interacting with pfctl command and parsing its output
    """
    read_cmd = ["/sbin/pfctl", "-vvsI", "-i", Conf.wan_if]

    def __init__(self):
        self.values = {}
        self.values_sum = {}
        self.last_values = {}
        self._reset_values()
        self._reset_last_values()
        self.interface_raw = None
        self.timestamp = None

    def _calc_values_sum(self):
        # zero, then sum
        for sumtype in self.counted_sum:
            self.values_sum[sumtype] = 0
        for sumtype in self.counted_sum:
            for counted_key, counted_val in self.values.items():
                if sumtype in counted_key or sumtype == 'All':
                    self.values_sum[sumtype] += counted_val

    def _read_interface(self):
        proc = subprocess.Popen(self.read_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode != 0:
            syslog.syslog("Failed to read pf interface usage from ", Conf.wan_if)
            syslog.syslog(stderr)
            return
        self.interface_raw = stdout

    def _reset_values(self):
        for key in self.counted:
            self.values[key] = 0

    def _reset_last_values(self):
        for key in self.counted:
            self.last_values[key] = 0

    def _parse_raw(self):
        """
        Consume raw collection into dictionary for things we care about.  See self.counted
        :return:
        """
        self.last_values = self.values
        self._reset_values()
        self.timestamp = time.time()

        for line in self.interface_raw.splitlines():
            try:
                line_l = line.split()
                if_key, if_value = [line_l[i] for i in (0,5)]
                if_key = if_key.rstrip(":")
                if if_key in self.counted:
                    self.values[if_key] = int(if_value.rstrip(']'))
            except IndexError:
                pass

    def process_interface(self):
        self._read_interface()
        self._parse_raw()
        self._calc_values_sum()

    def __str__(self):
        return time.ctime(self.timestamp) + " :" + repr(self.values) + repr(self.values_sum)


def main():
    Conf.system_config_filename = "/tmp/test/config.xml"

    Conf.read_conf()

    print "wan interface", Conf.wan_if
    print "reset day", Conf.settings['reset_day']

    pf = PfCtl()
    pf.process_interface()
    print pf
    sleep(60)
    next = PfCtl()
    next.process_interface()
    print next
    print repr(IntervalDiff(pf, next))

if __name__ == "__main__":

    main()
