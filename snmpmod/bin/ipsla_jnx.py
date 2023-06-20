"""
SNMP IPSLA Statistics Modular Input
"""

from __future__ import print_function
import time
import logging
from datetime import datetime

import snmputils
from pysnmp.error import PySnmpError
from pysnmp.proto.rfc1905 import NoSuchInstance
import sys

from SnmpStanza import SnmpStanza
from snmputils import splunk_escape, print_validation_error, print_xml_single_instance_mode, SnmpException


class Ipsla(SnmpStanza):
    def __init__(self):
        SnmpStanza.__init__(self)

    def operations(self):
        operations_str = self.conf.get("operations", None)
        if operations_str is None:
            return []
        return [str(x.strip()) for x in operations_str.split(',')]

    def is_valid(self):
        valid = SnmpStanza.is_valid(self)
        if self.operations() is None or len(self.operations()) < 1:
            print_validation_error("operations must contain at least one operation")
            valid = False

        return valid

    def scheme(self):
        return """<scheme>
    <title>IPSLA Statistics</title>
    <description>SNMP input to poll IPSLA statistics</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>
            <arg name="name">
                <title>IPSLA Statistic Name</title>
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
            <arg name="operations">
                <title>operations</title>
                <description>
                    1 or more ipsla statistic operations
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


# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.4.1.9.9.42.1.5.2.1.1
# http://www.oidview.com/mibs/9/CISCO-RTTMON-MIB.html
symbols = {
    '1.3.6.1.4.1.2636.3.7.1.5.1.6': 'latestRttCompletionTime',
    '1.3.6.1.4.1.2636.3.7.1.5.1.2': 'jnxPingLastTestResultSentProbes',
    '1.3.6.1.4.1.2636.3.7.1.5.1.1': 'jnxPingLastTestResultProbeResponses',
    '1.3.6.1.4.1.2636.3.7.1.3.1.20': 'latestRttOperationResponse',
}

runner = Ipsla()


# noinspection PyBroadException
def do_run():
    runner.read_config()
    snmputils.set_logger_format(name=runner.name())

    cmd_gen = snmputils.get_cmd_gen()

    while True:
        try:
            for operation in runner.operations():
                try:
                    oid_args = [str(b + '.' + operation) for b in symbols]
                    var_binds = snmputils.query_oids(cmd_gen, runner.security_object(), runner.transport(), oid_args)
                    handle_output(var_binds, runner.destination(), operation)
                except SnmpException as ex:
                    logging.error('error=%s msg=%s operation=%s', splunk_escape(ex.error_type),
                                  splunk_escape(ex.msg), operation)
                    break
        except PySnmpError as ex:
            logging.error('msg=%s', splunk_escape(ex))
        except Exception:
            logging.exception("Exception with getCmd to %s:%s" % (runner.destination(), runner.port))

        time.sleep(float(runner.snmpinterval()))


def get_symbol(mib):
    base_mib = str(mib[0:-1])
    if base_mib in symbols:
        return symbols[base_mib]
    # Juniper fix
    elif '1.3.6.1.4.1.2636.3.7.1.5.1.6' in base_mib:
        return 'latestRttCompletionTime'
    elif '1.3.6.1.4.1.2636.3.7.1.5.1.2' in base_mib:
        return 'jnxPingLastTestResultSentProbes'
    elif '1.3.6.1.4.1.2636.3.7.1.5.1.1' in base_mib:
        return 'jnxPingLastTestResultProbeResponses'
    elif '1.3.6.1.4.1.2636.3.7.1.3.1.20' in base_mib:
        return 'latestRttOperationResponse'
    else:
        return 'unknown'


def handle_output(response_object, destination, operation):
    splunkevent = "%s operation=%s " % (datetime.isoformat(datetime.utcnow()), operation)

    nvpairs = [(get_symbol(name), splunk_escape(val.prettyPrint()))
               for (name, val) in response_object
               if not isinstance(val, NoSuchInstance)]
    if len(nvpairs) > 0:
        splunkevent += ' '.join(['%s=%s' % nvp for nvp in nvpairs])
        print_xml_single_instance_mode(destination, splunkevent)
    else:
        logging.error('msg="No data for operation" operation=%s', operation)
    sys.stdout.flush()


# noinspection PyBroadException
def do_validate():
    try:
        runner.read_config()
        if not runner.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception:
        logging.exception("Exception validating")
        sys.exit(1)


def do_scheme():
    print(runner.scheme())


def usage():
    print("usage: %s [--scheme|--validate-arguments]")
    logging.error("Incorrect Program Usage")
    sys.exit(2)


if __name__ == '__main__':
    # Because I always forget how to enable debug logging
    # http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsLog
    logging.basicConfig(level=logging.INFO, format=snmputils.logging_format_string)

    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            do_validate()
        elif sys.argv[1] == "--debug":
            logging.root.setLevel(logging.DEBUG)
            do_run()
        else:
            usage()
    else:
        do_run()
    sys.exit(0)
