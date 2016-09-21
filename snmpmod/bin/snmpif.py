"""
SNMP Interface Modular Input
"""

import time

import snmputils
from pysnmp.error import PySnmpError
from snmputils import SnmpException
from SnmpStanza import *


class SnmpIf(SnmpStanza):
    def __init__(self):
        SnmpStanza.__init__(self)

    def interfaces(self):
        interfaces_str = self.conf.get("interfaces", None)
        if interfaces_str is None:
            return []
        return [str(x.strip()) for x in interfaces_str.split(',')]

    def is_valid(self):
        valid = SnmpStanza.is_valid(self)
        if self.interfaces() is None or len(self.interfaces()) < 1:
            print_validation_error("Interfaces must contain at least one interface")
            valid = False

        return valid

    def scheme(self):
        return """<scheme>
    <title>SNMP Interface</title>
    <description>SNMP input to poll interfaces</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>
            <arg name="name">
                <title>SNMP Input Name</title>
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
                <title>Interfaces</title>
                <description>
                    1 or more interface numbers to poll
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


snmpif = SnmpIf()

# These are all the OIDs for an interface from IF-MIB::
# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.2.1.2.2.1.1
# http://www.oidview.com/mibs/0/IF-MIB.html
interface_mibs = {'1.3.6.1.2.1.2.2.1.1': 'ifIndex',
                  '1.3.6.1.2.1.2.2.1.2': 'ifDescr',
                  '1.3.6.1.2.1.2.2.1.3': 'ifType',
                  '1.3.6.1.2.1.2.2.1.4': 'ifMtu',
                  '1.3.6.1.2.1.2.2.1.5': 'ifSpeed',
                  '1.3.6.1.2.1.2.2.1.6': 'ifPhysAddress',
                  '1.3.6.1.2.1.2.2.1.7': 'ifAdminStatus',
                  '1.3.6.1.2.1.2.2.1.8': 'ifOperStatus',
                  '1.3.6.1.2.1.2.2.1.9': 'ifLastChange',
                  '1.3.6.1.2.1.2.2.1.10': 'ifInOctets',
                  '1.3.6.1.2.1.2.2.1.11': 'ifInUcastPkts',
                  '1.3.6.1.2.1.2.2.1.12': 'ifInNUcastPkts',
                  '1.3.6.1.2.1.2.2.1.13': 'ifInDiscards',
                  '1.3.6.1.2.1.2.2.1.14': 'ifInErrors',
                  '1.3.6.1.2.1.2.2.1.15': 'ifInUnknownProtos',
                  '1.3.6.1.2.1.2.2.1.16': 'ifOutOctets',
                  '1.3.6.1.2.1.2.2.1.17': 'ifOutUcastPkts',
                  '1.3.6.1.2.1.2.2.1.18': 'ifOutNUcastPkts',
                  '1.3.6.1.2.1.2.2.1.19': 'ifOutDiscards',
                  '1.3.6.1.2.1.2.2.1.20': 'ifOutErrors',
                  '1.3.6.1.2.1.2.2.1.21': 'ifOUtQLen',
                  '1.3.6.1.2.1.2.2.1.22': 'ifSpecific',
                  '1.3.6.1.2.1.31.1.1.1.6': 'ifHCInOctets',
                  '1.3.6.1.2.1.31.1.1.1.7': 'ifHCInUcastPkts',
                  '1.3.6.1.2.1.31.1.1.1.10': 'ifHCOutOctets',
                  '1.3.6.1.2.1.31.1.1.1.11': 'ifHCOutUcastPkts',
                  }


# noinspection PyBroadException
def do_run():
    snmpif.read_config()
    snmputils.set_logger_format(name=snmpif.name())

    cmd_gen = snmputils.get_cmd_gen()

    while True:
        try:
            startTime = time.time()
            endTime = 0
            for interface in snmpif.interfaces():
                oid_args = [str(b + '.' + interface) for b in interface_mibs.keys()]
                logging.debug('oid_args=%s', oid_args)
                var_binds = snmputils.query_oids(cmd_gen, snmpif.security_object(), snmpif.transport(), oid_args)
                logging.debug('var_binds=%s', var_binds)
                handle_output(var_binds, snmpif.destination())

            endTime = time.time()

        except SnmpException as ex:
            logging.error('error=%s msg=%s interfaces=%s', splunk_escape(ex.error_type),
                          splunk_escape(ex.msg), splunk_escape(','.join(snmpif.interfaces())))
        except PySnmpError as ex:
            logging.error('msg=%s', splunk_escape(ex.message))
        except Exception:
            logging.exception('msg="Exception in main loop"')

        interval = int(snmpif.snmpinterval())
        runningTime = endTime - startTime
        if (runningTime > 0 ) and (runningTime < interval):
            time.sleep(interval-runningTime)


def get_symbol(mib):
    base_mib = str(mib[0:-1])
    return interface_mibs[base_mib]


def get_interface(mib):
    return str(mib[-1])


def create_snmpif_splunk_event(response_object):
    from datetime import datetime
    from pysnmp.proto.rfc1905 import NoSuchInstance
    splunkevent = "%s " % (datetime.isoformat(datetime.utcnow()))

    nvpairs = [(get_symbol(name), snmputils.splunk_escape(val.prettyPrint()))
               for (name, val) in response_object
               if not isinstance(val, NoSuchInstance)]
    logging.debug('nvpairs=%s', nvpairs)
    if len(nvpairs) > 0:
        splunkevent += ' '.join(['%s=%s' % nvp for nvp in nvpairs])
        return splunkevent
    else:
        mib, _ = response_object[0]
        logging.error('msg="No data for interface" interface=%s', get_interface(mib))
        return None


def handle_output(response_object, destination):
    splunkevent = create_snmpif_splunk_event(response_object)
    if splunkevent is not None:
        snmputils.print_xml_single_instance_mode(destination, splunkevent)
    sys.stdout.flush()


# noinspection PyBroadException
def do_validate():
    try:
        snmpif.read_config()
        if not snmpif.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception:
        logging.exception("Exception validating")
        sys.exit(1)


def do_scheme():
    print snmpif.scheme()


def usage():
    print "usage: %s [--scheme|--validate-arguments]"
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
