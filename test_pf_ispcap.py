import unittest
import StringIO
import pf_ispcap

first = """\
igb0
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
        self.assertEqual(pf_ispcap.Conf.wan_if, "igb0")

    def test_reset_day(self):
        self.assertEqual(pf_ispcap.Conf.settings['reset_day'], 2)

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
            self.assertEqual(self.start.values[start_key], start_val)

        _stop_values = (78438271821, 1337700, 2971407561, 22073733513, 2630798, 1796213111)
        stop_values = dict(zip(self.stop.counted, _stop_values))
        for stop_key, stop_val in stop_values.items():
            self.assertTrue(stop_key in self.stop.values)
            self.assertEqual(self.stop.values[stop_key], stop_val)

    def testInOut(self):
        self.assertEqual(self.start.values_sum['In'], 78438191152 + 1337478 + 22073635368 + 2630798)
        self.assertEqual(self.start.values_sum['Out'], 2971388050 + 1796168437)

    def testIntervalDiff(self):
        i_diff = pf_ispcap.IntervalDiff(self.start, self.stop)
        self.assertEqual(i_diff.diff['In'], 78438271821 + 1337700 + 22073733513 + 2630798
                         - 78438191152 - 1337478 - 22073635368 - 2630798)
        self.assertEqual(i_diff.diff['Out'], 2971407561 + 1796213111
                         - 2971388050 - 1796168437)

if __name__ == '__main__':
    unittest.main()
