"""
SNMP IPSLA Statistics Modular Input
"""

import time
from datetime import datetime


import snmputils
from SnmpStanza import *
import pysnmp.proto.rfc1905


class Qos(SnmpStanza):
    # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?local=en&translate=Translate&objectInput=1.3.6.1.4.1.9.9.166.1.15.1.1
    # Valid QoS statistics
    statistics = {
        '7': 'prePolicyBitRate',
        '11': 'postPolicyBitRate',
        '18': 'dropBitRate',
    }

    def __init__(self):
        SnmpStanza.__init__(self)
        self.cmd_gen, self.mib_view = snmputils.get_cmd_gen([])

    def interfaces(self):
        interfaces_str = self.conf.get("interfaces", None)
        if interfaces_str is None:
            return []
        return [str(x.strip()) for x in interfaces_str.split(',')]

    def stats(self):
        stats_str = self.conf.get("stats", None)
        if stats_str is None:
            return self.statistics.values()

        return [str(x.strip()) for x in stats_str.split(',')]

    def stats_keys(self):
        def get_stat_val(name):
            return next((sv for sv, sn in self.statistics.iteritems() if sn == name))
        return [get_stat_val(s) for s in self.stats()]

    def is_valid(self):
        valid = SnmpStanza.is_valid(self)
        if self.interfaces() is None or len(self.interfaces()) < 1:
            print_validation_error("interfaces must contain at least one interface")
            valid = False
        if self.stats() is not None and len(self.stats()) > 0:
            if not set(self.stats()).issubset(set(self.statistics.values())):
                print_validation_error("invalid stats value found")
                valid = False

        return valid

    def scheme(self):
        return """<scheme>
    <title>QOS Config Map Statistics</title>
    <description>SNMP input to poll QOS Config Map statistics</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>
            <arg name="name">
                <title>QOS Name</title>
                <description>Name of this SNMP input</description>
            </arg>
            <arg name="destination">
                <title>Destination</title>
                <description>IP or hostname of the device you would like to query</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="ipv6">
                <title>IP Version 6</title>
                <description>Whether or not this is an IP version 6 address. Defaults to false</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="port">
                <title>Port</title>
                <description>The SNMP port. Defaults to 161</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="snmp_version">
                <title>SNMP Version</title>
                <description>The SNMP Version , 1 or 2C, version 3 not currently supported. Defaults to 2C</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="interfaces">
                <title>interfaces</title>
                <description>
                    1 or more interfaces
                </description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="stats">
                <title>interfaces</title>
                <description>
                    1 or more statistics to poll for each interface
                </description>
                <required_on_edit>true</required_on_edit>
                <required_on_create>true</required_on_create>
            </arg>
            <arg name="communitystring">
                <title>Community String</title>
                <description>Community String used for authentication.Defaults to "public"</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="v3_securityName">
                <title>SNMPv3 USM Username</title>
                <description>SNMPv3 USM Username</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="v3_authKey">
                <title>SNMPv3 Authorization Key</title>
                <description>
                    SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a
                    non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take
                    effect. Default hashing method may be changed by means of further authProtocol parameter
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="v3_privKey">
                <title>SNMPv3 Encryption Key</title>
                <description>
                    SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty
                    value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based
                    encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption
                    methods may be changed by means of further authProtocol and/or privProtocol parameters.
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="v3_authProtocol">
                <title>SNMPv3 Authorization Protocol</title>
                <description>
                    may be used to specify non-default hash function algorithm. Possible values include
                    usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="v3_privProtocol">
                <title>SNMPv3 Encryption Key Protocol</title>
                <description>
                    may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol
                    (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol /
                    usmAesCfb256Protocol / usmNoPrivProtocol
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="snmpinterval">
                <title>Interval</title>
                <description>How often to run the SNMP query (in seconds). Defaults to 60 seconds</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""

    def query_oids(self, oids):
        return self.cmd_gen.getCmd(runner.security_object(), runner.transport(), *oids)

    def walk_oids(self, oids):
        return self.cmd_gen.nextCmd(runner.security_object(), runner.transport(), *oids)

    def get_policy_indexes(self):
        """
        Get the policy indexes for all configured interfaces
        :return: A dictionary that has the policy index as the key and a tuple of (interface, direction) as the value
        {
            'policyIndex': ('interface', 'direction'),
            '836311857': ('324', 'in'),
            '836311858': ('324', 'out')
        }
        """
        oids = [str('1.3.6.1.4.1.9.9.166.1.2.1.1.1.' + i) for i in self.interfaces()]
        e_indication, e_status, e_index, res = self.walk_oids(oids)
        if e_indication:
            logging.error(e_indication)
        elif e_status:
            logging.error(e_status)
        else:
            # output looks like
            # iso.3.6.1.4.1.9.9.166.1.2.1.1.1.324.1 = Gauge32: 836311857 <- policy index
            # iso.3.6.1.4.1.9.9.166.1.2.1.1.1.324.2 = Gauge32: 836311858
            policy_indexes = {}
            # res is a list of single item lists.  Flatten it
            for [name, val] in [r for sublist in res for r in sublist]:
                if not isinstance(val, pysnmp.proto.rfc1905.NoSuchInstance):
                    # For direction, 1 is in, 2 is out
                    direction = 'in' if name[-1] == 1 else 'out'
                    interface = str(name[-2])
                    policy_index = val.prettyPrint()
                    policy_indexes[policy_index] = (interface, direction)
            return policy_indexes

    def get_config_indexes(self, indexes):
        """
        Get the config indexes for all policy & object indexes.

        indexes is a list of (policy_index, object_index)
        :return:
        {
            ('policy_index', 'object_index'): 'config_index'
        }
        """
        oids = [str('1.3.6.1.4.1.9.9.166.1.5.1.1.2.' + policy_index + '.' + object_index) for policy_index, object_index
                in indexes]
        e_indication, e_status, e_index, res = self.query_oids(oids)
        # output looks like
        # iso.3.6.1.4.1.9.9.166.1.5.1.1.2.836311857.601391474 = Gauge32: 1965376995

        config_indexes = {}
        if e_indication:
            logging.error(e_indication)
        elif e_status:
            logging.error(e_status)
        else:
            for name, val in res:
                if not isinstance(val, pysnmp.proto.rfc1905.NoSuchInstance):
                    policy_index = str(name[-2])
                    object_index = str(name[-1])
                    value = str(val.prettyPrint())
                    config_indexes[(policy_index, object_index)] = value
        return config_indexes

    def get_statistics(self, policy_indexes, class_maps):
        """
        Get the config map statistics for all the policy indexes
        :param class_maps: Class maps
        :param policy_indexes: policy indexes
        :return:
        {
            'object_index': ('policy_index', 'statistic', 'class_map', 'value'),
            '601391474': ('836311857', '7', 'REAL-TIME', '59392'),
        }
        """

        print self.stats_keys()
        oids = ['1.3.6.1.4.1.9.9.166.1.15.1.1.' + str(stat + '.' + index) for stat, index in
                zip(self.stats_keys(), policy_indexes.keys())]
        e_indication, e_status, e_index, res = self.walk_oids(oids)
        # output looks like
        # iso.3.6.1.4.1.9.9.166.1.15.1.1.7.836311857.601391474 = Gauge32: 59392
        #                      statistic ^.policy  ^.objInd ^^ =          ^^^ statistic value
        stats_results = {}
        if e_indication:
            logging.error(e_indication)
        elif e_status:
            logging.error(e_status)
        else:
            c_ind = []
            flat_result = [r for sublist in res for r in sublist]
            for [name, _] in flat_result:
                c_ind.append((str(name[-2]), str(name[-1])))
            config_indexes = self.get_config_indexes(c_ind)
            logging.debug("config_indexes=" + str(config_indexes))

            for name, val in flat_result:
                statistic = self.statistics[str(name[-3])]
                policy_index = str(name[-2])
                object_index = str(name[-1])
                value = str(val.prettyPrint())
                config_index = config_indexes[(policy_index, object_index)]
                class_map = class_maps[config_index]
                stats_results[object_index] = (policy_index, statistic, class_map, value)
        return stats_results

    def run_once(self):
        try:
            class_maps = self.get_class_maps()
            logging.debug("class_maps=" + str(class_maps))
            policy_indexes = self.get_policy_indexes()
            logging.debug("policy_indexes=" + str(policy_indexes))
            statistics = self.get_statistics(policy_indexes, class_maps)
            logging.debug("statistics=" + str(statistics))
            events = {}
            for object_index, stats in statistics.iteritems():
                policy_index, statistic, class_map, value = stats
                interface, direction = policy_indexes[policy_index]
                key = (interface, direction, class_map)
                if key not in events:
                    events[key] = []
                events[key].append((statistic, value))

            logging.debug("events=" + str(events))

            for (interface, direction, class_map), vals in events.iteritems():
                splunkevent = "%s interface=%s direction=%s class_map=%s" % (datetime.isoformat(datetime.utcnow()),
                                                                             interface, direction,
                                                                             snmputils.splunk_escape(class_map))

                for statistic, value in vals:
                    splunkevent += ' %s=%s' % (statistic, value)
                snmputils.print_xml_single_instance_mode(self.destination(), splunkevent)
            sys.stdout.flush()

        except Exception as ex:  # catch *all* exceptions
            logging.exception("Exception with getCmd to %s:%s %s" % (self.destination(), self.port(), ex))
            time.sleep(float(runner.snmpinterval()))

    def get_class_maps(self):
        """
        Get the class map config table once for the whole run

        http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.4.1.9.9.166.1.7.1.1.1&translate=Translate&submitValue=SUBMIT&submitClicked=true
        :return:
        {
            'configIndex': 'classmap-name',
            '70104689': 'REAL-TIME',
            '1965376995': 'class-default',
        }
        """
        class_maps = {}
        e_indication, e_status, e_index, res = self.walk_oids(['1.3.6.1.4.1.9.9.166.1.7.1.1.1'])
        # iso.3.6.1.4.1.9.9.166.1.7.1.1.1.1819748200 = STRING: "ef"
        # iso.3.6.1.4.1.9.9.166.1.7.1.1.1.1965376995 = STRING: "class-default"
        if e_indication:
            logging.error(e_indication)
        elif e_status:
            logging.error(e_status)
        else:
            for r in res:
                name, val = r[0]
                class_maps[str(name[-1])] = str(val.prettyPrint())
        return class_maps


runner = Qos()


def do_run(debug=False):
    if debug:
        logging.root.setLevel('DEBUG')
    runner.read_config()

    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                h.setFormatter(logging.Formatter('%(levelname)s qos="{0}" %(message)s'.format(runner.name())))

    except Exception as e:  # catch *all* exceptions
        logging.exception("Couldn't update logging templates: %s" % e)

    try:
        while True:
            runner.run_once()
            time.sleep(float(runner.snmpinterval()))

    except Exception as ex:
        logging.exception("Exception in run: %s" % ex)
        sys.exit(1)


def do_validate():
    try:
        runner.read_config()
        if not runner.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception as ex:
        logging.exception("Exception validating %s" % ex)
        sys.exit(1)


def do_scheme():
    print runner.scheme()


def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    logging.error("Incorrect Program Usage")
    sys.exit(2)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            do_validate()
        elif sys.argv[1] == "--debug":
            do_run(debug=True)
        else:
            usage()
    else:
        do_run()
    sys.exit(0)
