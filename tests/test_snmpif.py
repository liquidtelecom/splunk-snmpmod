import logging
import unittest

import sys
from hamcrest import *

import snmpif
from pysnmp.proto.rfc1902 import *
from pysnmp.proto.rfc1902 import ObjectName
from pysnmp.proto.rfc1905 import NoSuchInstance

logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


class SnmpifTests(unittest.TestCase):
    def test_create_snmpif_splunk_event(self):
        var_binds = [(ObjectName('1.3.6.1.2.1.2.2.1.1.86'), Gauge32(86)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.2.86'), OctetString('Bundle-Ether1')),
                     (ObjectName('1.3.6.1.2.1.2.2.1.3.86'), OctetString('ieee8023adLag')),
                     (ObjectName('1.3.6.1.2.1.2.2.1.4.86'), Integer32(1514)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.5.86'), Gauge32(4294967295)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.6.86'), OctetString('a8:0c:0d:6d:bd:7b')),
                     (ObjectName('1.3.6.1.2.1.2.2.1.7.86'), OctetString('up')),
                     (ObjectName('1.3.6.1.2.1.2.2.1.8.86'), OctetString('up')),
                     (ObjectName('1.3.6.1.2.1.2.2.1.9.86'), TimeTicks(845466098)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.10.86'), Counter32(2876455120)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.11.86'), Counter32(3400599021)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.12.86'), NoSuchInstance()),
                     (ObjectName('1.3.6.1.2.1.2.2.1.13.86'), Counter32(0)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.14.86'), Counter32(0)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.15.86'), Counter32(17)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.16.86'), Counter32(3388716632)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.17.86'), Counter32(910069109)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.18.86'), NoSuchInstance()),
                     (ObjectName('1.3.6.1.2.1.2.2.1.19.86'), Counter32(0)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.20.86'), Counter32(0)),
                     (ObjectName('1.3.6.1.2.1.2.2.1.21.86'), NoSuchInstance()),
                     (ObjectName('1.3.6.1.2.1.2.2.1.22.86'), NoSuchInstance()),
                     (ObjectName('1.3.6.1.2.1.31.1.1.1.6.86'), Counter64(10834783975632)),
                     (ObjectName('1.3.6.1.2.1.31.1.1.1.7.86'), Counter64(7695566317)),
                     (ObjectName('1.3.6.1.2.1.31.1.1.1.10.86'), Counter64(2889606739544)),
                     (ObjectName('1.3.6.1.2.1.31.1.1.1.11.86'), Counter64(9500003701))]
        expected = 'ifIndex=86 ifDescr=Bundle-Ether1 ifType=ieee8023adLag ifMtu=1514 ifSpeed=4294967295 ifPhysAddress=a8:0c:0d:6d:bd:7b ifAdminStatus=up ifOperStatus=up ifLastChange=845466098 ifInOctets=2876455120 ifInUcastPkts=3400599021 ifInDiscards=0 ifInErrors=0 ifInUnknownProtos=17 ifOutOctets=3388716632 ifOutUcastPkts=910069109 ifOutDiscards=0 ifOutErrors=0 ifHCInOctets=10834783975632 ifHCInUcastPkts=7695566317 ifHCOutOctets=2889606739544 ifHCOutUcastPkts=9500003701'
        actual = snmpif.create_snmpif_splunk_event(var_binds)

        assert_that(actual, ends_with(expected))
