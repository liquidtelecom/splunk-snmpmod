"""
SNMP Interface Modular Input for Ekinops switches
"""

import time
import socket
import snmputils
from pysnmp.error import PySnmpError
from snmputils import SnmpException
from SnmpStanza import *
from pysnmp.proto import rfc1902

class SnmpEkinops(SnmpStanza):
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


snmpEkinops = SnmpEkinops()

# These are all the OIDs for an interface from IF-MIB::
# http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.2.1.2.2.1.1
# http://www.oidview.com/mibs/0/IF-MIB.html
interface_mibs = {  'pm1001lhMesrlineRxPowerMeas':'1.3.6.1.4.1.20044.10.3.3.212',
                    'pm1001lhMesrlineTxPowerMeas':'1.3.6.1.4.1.20044.10.3.3.211',
                    'pmoabMesrclientEdfaRxpwrMeas':'1.3.6.1.4.1.20044.23.3.2.34',
                    'pmoabMesrlineEdfaTxpwrMeas':'1.3.6.1.4.1.20044.23.3.3.41',
                    'pmoabMesrlineEdfaGainMeas':'1.3.6.1.4.1.20044.23.3.3.43',
                    'pmopsMesrcomaTxPower1':'1.3.6.1.4.1.20044.30.3.2.16',
                    'pmopsMesrcomaTxPower2':'1.3.6.1.4.1.20044.30.3.2.17',
                    'pmopsMesrcomaRxPower1':'1.3.6.1.4.1.20044.30.3.2.18',
                    'pmopsMesrcomaRxPower2':'1.3.6.1.4.1.20044.30.3.2.19',
                    'pmoailMesrclientEdfaGainMeas':'1.3.6.1.4.1.20044.36.3.2.35',
                  }

inv_interface_mibs = {v: k for k, v in interface_mibs.items()}

managed_oids = {    'PMC1001HC':['pm1001lhMesrlineRxPowerMeas','pm1001lhMesrlineTxPowerMeas'],
                    'PMOABP-E':['pmoabMesrclientEdfaRxpwrMeas','pmoabMesrlineEdfaTxpwrMeas','pmoabMesrlineEdfaGainMeas'],
                    'PMOPS':['pmopsMesrcomaTxPower1','pmopsMesrcomaTxPower2','pmopsMesrcomaRxPower1','pmopsMesrcomaRxPower2'],
                    'PMOAIL-E':['pmoailMesrclientEdfaGainMeas']
               }

mgnt2GigmSelectedBoard = "1.3.6.1.4.1.20044.7.1.2.7.0"
mgnt2Position = "1.3.6.1.4.1.20044.7.1.2.1.1.2"

# noinspection PyBroadException
def do_run():
    snmpEkinops.read_config()
    snmputils.set_logger_format(name=snmpEkinops.name())

    cmd_gen = snmputils.get_cmd_gen()

    while True:
        try:
            for interface in snmpEkinops.interfaces():
                interfaceId = interface.split(':')[0]
                cardType = interface.split(':')[1]
                ipAddr = socket.gethostbyname(snmpEkinops.destination())

                # Get the card number
                oid_args = [mgnt2Position + "." + interfaceId]
                logging.debug('get card number, oid_args=%s', oid_args)
                var_binds = snmputils.query_ekinops_card(cmd_gen, snmpEkinops.security_object(), snmpEkinops.transport(),oid_args)
                card_number = var_binds[0][1].prettyPrint()

                # Set card to read from
                oid_args = [str(mgnt2GigmSelectedBoard), rfc1902.Integer(card_number)]
                logging.debug('set card number, oid_args=%s', oid_args)
                snmp_result = cmd_gen.setCmd(snmpEkinops.security_object(), snmpEkinops.transport(), oid_args)

                # Create array of oids to read
                oid_args = [interface_mibs[e] + ".0" for e in managed_oids[cardType]]
                logging.debug('queryOids, oid_args=%s', oid_args)
                var_binds = snmputils.query_oids(cmd_gen, snmpEkinops.security_object(), snmpEkinops.transport(), oid_args)
                logging.debug('var_binds=%s', var_binds)

                interface_attrs = {}
                interface_attrs['card'] = card_number
                interface_attrs['interfaceIdx'] = interfaceId
                interface_attrs['cardType'] = cardType
                interface_attrs['ipAddr'] = ipAddr

                handle_output(var_binds, snmpEkinops.destination(), interface_attrs)

        except SnmpException as ex:
            logging.error('error=%s msg=%s interfaces=%s', splunk_escape(ex.error_type),
                          splunk_escape(ex.msg), splunk_escape(','.join(snmpEkinops.interfaces())))
        except PySnmpError as ex:
            logging.error('msg=%s', splunk_escape(ex.message))
        except Exception:
            logging.exception('msg="Exception in main loop"')

        time.sleep(float(snmpEkinops.snmpinterval()))


def get_symbol(mib):
    base_mib = str(mib[0:-1])
    return inv_interface_mibs[base_mib]


def get_interface(mib):
    return str(mib[-1])


def create_snmpEkinops_splunk_event(response_object, interface_attrs):
    from datetime import datetime
    from pysnmp.proto.rfc1905 import NoSuchInstance
    splunkevent = "%s " % (datetime.isoformat(datetime.utcnow()))

    nvpairs = [(get_symbol(name), snmputils.splunk_escape(val.prettyPrint()))
               for (name, val) in response_object
               if not isinstance(val, NoSuchInstance)]
    logging.debug('nvpairs=%s', nvpairs)
    if len(nvpairs) > 0:
        splunkevent += ' '.join(['%s=%s' % nvp for nvp in nvpairs])
        for key, value in interface_attrs.iteritems():
            splunkevent += ' ' + key + '=' + value
        return splunkevent
    else:
        mib, _ = response_object[0]
        logging.error('msg="No data for interface" interface=%s', get_interface(mib))
        return None


def handle_output(response_object, destination, interface_attrs):
    splunkevent = create_snmpEkinops_splunk_event(response_object, interface_attrs)
    if splunkevent is not None:
        snmputils.print_xml_single_instance_mode(destination, splunkevent)
    sys.stdout.flush()


# noinspection PyBroadException
def do_validate():
    try:
        snmpEkinops.read_config()
        if not snmpEkinops.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception:
        logging.exception("Exception validating")
        sys.exit(1)


def do_scheme():
    print snmpEkinops.scheme()


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
