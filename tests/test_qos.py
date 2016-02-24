import logging
import unittest

import sys
from hamcrest import *

import qos
from pysnmp.proto.rfc1902 import ObjectName, OctetString, Gauge32
from qos import PolicyIndex
from snmputils import SnmpException

logger = logging.getLogger()
logger.level = logging.DEBUG
stream_handler = logging.StreamHandler(sys.stdout)
logger.addHandler(stream_handler)


class QosFunctionTests(unittest.TestCase):
    @staticmethod
    def test_extract_classmaps():
        table = [[(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.748129779'), OctetString('cs6'))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.1201419584'), OctetString('af4'))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.1201419589'), OctetString('af1'))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.1201419590'), OctetString('af2'))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.1819748200'), OctetString('ef'))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.7.1.1.1.1965376995'), OctetString('class-default'))]]
        class_maps = qos.extract_classmaps_from(table)
        expected = {'748129779': 'cs6', '1201419589': 'af1', '1201419584': 'af4', '1201419590': 'af2',
                    '1965376995': 'class-default', '1819748200': 'ef'}
        assert_that(class_maps, has_entries(expected))

    def test_extract_classmaps_empty(self):
        self.assertRaises(SnmpException, qos.extract_classmaps_from, [])

    @staticmethod
    def test_extract_policy_indexes():
        table = [[(ObjectName('1.3.6.1.4.1.9.9.166.1.2.1.1.1.155.1'), Gauge32(1654707672))],
                 [(ObjectName('1.3.6.1.4.1.9.9.166.1.2.1.1.1.155.2'), Gauge32(996352128))]]

        expected = {'996352128': PolicyIndex('155', 'out'), '1654707672': PolicyIndex('155', 'in')}

        actual = qos.extract_policy_interface_indexes(table)

        assert_that(actual, has_entries(expected))

    def test_extract_policy_indexes_empty(self):
        self.assertRaises(SnmpException, qos.extract_policy_interface_indexes, [])

    @staticmethod
    def test_extract_cm_stats_table():
        table = [[(ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.7.996352128.759637879'), Gauge32(193536)),
                  (ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.7.1654707672.1924233547'), Gauge32(1580032)),
                  (ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.11.996352128.759637879'), Gauge32(0)),
                  (ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.11.1654707672.1924233547'), Gauge32(0)),
                  (ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.18.996352128.759637879'), Gauge32(0)),
                  (ObjectName('1.3.6.1.4.1.9.9.166.1.15.1.1.18.1654707672.1924233547'), Gauge32(153600))]]

        expected = [('996352128', '759637879'), ('1654707672', '1924233547'), ('996352128', '759637879'),
                    ('1654707672', '1924233547'), ('996352128', '759637879'), ('1654707672', '1924233547')]
        actual = qos.extract_classmap_stats(table)
        assert_that(actual, contains_inanyorder(*expected))
