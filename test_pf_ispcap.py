import unittest
import StringIO
import pf_ispcap

first = """\
igb0
	Cleared:     Fri Apr 22 14:22:28 2016
	References:  46
	In4/Pass:    [ Packets: 60939634           Bytes: 78438191152        ]
	In4/Block:   [ Packets: 19863              Bytes: 1337478            ]
	Out4/Pass:   [ Packets: 30772200           Bytes: 2971388050         ]
	Out4/Block:  [ Packets: 1                  Bytes: 40                 ]
	In6/Pass:    [ Packets: 35444914           Bytes: 22073635368        ]
	In6/Block:   [ Packets: 3817               Bytes: 2630798            ]
	Out6/Pass:   [ Packets: 13026489           Bytes: 1796168437         ]
	Out6/Block:  [ Packets: 1                  Bytes: 86                 ]
"""

second = """\
igb0
	Cleared:     Fri Apr 22 14:22:28 2016
	References:  46
	In4/Pass:    [ Packets: 60939948           Bytes: 78438271821        ]
	In4/Block:   [ Packets: 19866              Bytes: 1337700            ]
	Out4/Pass:   [ Packets: 30772514           Bytes: 2971407561         ]
	Out4/Block:  [ Packets: 1                  Bytes: 40                 ]
	In6/Pass:    [ Packets: 35445961           Bytes: 22073733513        ]
	In6/Block:   [ Packets: 3817               Bytes: 2630798            ]
	Out6/Pass:   [ Packets: 13026785           Bytes: 1796213111         ]
	Out6/Block:  [ Packets: 1                  Bytes: 86                 ]
"""

config = """\
<?xml version="1.0"?>
<pfsense>
        <version>15.0</version>
        <lastchange/>
        <theme>pfsense_ng</theme>
        <pf-ispcap>
        <reset_day>2</reset_day>
        </pf-ispcap>
        <interfaces>
        <wan>
        <if>igb0</if>
        </wan>
        </interfaces>
</pfsense>
"""

class TestConfig(unittest.TestCase):

    def setUp(self):
        self.config_fh = StringIO.StringIO(config)
        pf_ispcap.Conf.read_conf(self.config_fh)

    def test_interface(self):
        self.assertEqual( "igb0", pf_ispcap.Conf.wan_if)

    def test_reset_day(self):
        self.assertEqual( 2, pf_ispcap.Conf.settings['reset_day'])

class TestParse(unittest.TestCase):

    def setUp(self):
        self.config_fh = StringIO.StringIO(config)
        self.start = pf_ispcap.PfCtl()
        self.stop = pf_ispcap.PfCtl()
        self.start.interface_raw = first
        self.stop.interface_raw = second
        self.start._parse_raw()
        self.stop._parse_raw()
        self.start._calc_values_sum()
        self.stop._calc_values_sum()

    def testValues(self):
        _start_values = (78438191152, 1337478, 2971388050, 22073635368, 2630798, 1796168437)
        start_values = dict(zip(self.start.counted, _start_values))
        for start_key, start_val in start_values.items():
            self.assertTrue(start_key in self.start.values)
            self.assertEqual(start_val, self.start.values[start_key])

        _stop_values = (78438271821, 1337700, 2971407561, 22073733513, 2630798, 1796213111)
        stop_values = dict(zip(self.stop.counted, _stop_values))
        for stop_key, stop_val in stop_values.items():
            self.assertTrue(stop_key in self.stop.values)
            self.assertEqual(stop_val, self.stop.values[stop_key])

    def testCleared(self):
        self.assertEquals("2016-04-22T14:22:28", str(self.start.cleared))

    def testTimestampTime(self):
        ts = pf_ispcap.Timestamp(1462647526.178073)
        self.assertEquals('2016-05-07T11:58:46.178073', str(ts))

    def testTimestampParseISO(self):
        ts = pf_ispcap.Timestamp('2016-05-07T11:58:46.178073')
        self.assertEquals('2016-05-07T11:58:46.178073', str(ts))

    def testTimestampParseCtime(self):
        ts = pf_ispcap.Timestamp('Sat May  7 11:58:46 2016')
        self.assertEquals('2016-05-07T11:58:46', str(ts))

    def testInOut(self):
        self.assertEqual(78438191152 + 1337478 + 22073635368 + 2630798, self.start.values_sum['In'])
        self.assertEqual(2971388050 + 1796168437, self.start.values_sum['Out'])

    def testIntervalDiff(self):
        i_diff = pf_ispcap.IntervalDiff(self.start, self.stop)
        self.assertEqual(78438271821 + 1337700 + 22073733513 + 2630798 \
                         - 78438191152 - 1337478 - 22073635368 - 2630798, i_diff.diff['In'])
        self.assertEqual(2971407561 + 1796213111 - 2971388050 - 1796168437, i_diff.diff['Out'])

    def testIntervalDiffTimestamp(self):
        self.start.timestamp = pf_ispcap.Timestamp("Sat May  7 13:53:26 PDT 2016")
        self.stop.timestamp = pf_ispcap.Timestamp("Sat May  7 13:54:26 PDT 2016")
        i_diff = pf_ispcap.IntervalDiff(self.start, self.stop)
        self.assertEquals(60, i_diff.diff['time_delta'].total_seconds())

if __name__ == '__main__':
    unittest.main()
