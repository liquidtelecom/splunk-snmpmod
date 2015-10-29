"""
SNMP Interface Modular Input
"""

import time

import snmputils
from SnmpStanza import *

snmpif = SnmpIf()


class InterfaceResponseHandler:
    def __init__(self, **args):
        pass

    def __call__(self, response_object, destination):
        from responsehandlers import splunk_escape, print_xml_single_instance_mode
        from datetime import datetime
        from pysnmp.proto.rfc1905 import NoSuchInstance
        splunkevent = "%s " % (datetime.isoformat(datetime.utcnow()))
        for name, val in response_object:
            symbol = name.getMibSymbol()[1]
            if not isinstance(val, NoSuchInstance):
                splunkevent += '%s=%s ' % (symbol, splunk_escape(val.prettyPrint()))
        print_xml_single_instance_mode(destination, splunkevent)


def do_run():
    snmpif.read_config()

    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                h.setFormatter(logging.Formatter('%(levelname)s snmpif="{0}" %(message)s'.format(snmpif.name())))

    except Exception as e:  # catch *all* exceptions
        logging.exception("Couldn't update logging templates: %s" % e)

    # MIBs to load
    mib_names_args = ['IF-MIB']

    global mib_view
    cmd_gen, mib_view = snmputils.get_cmd_gen(mib_names_args)

    try:
        # These are all the OIDs for an interface from IF-MIB::
        # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.2.1.2.2.1.1
        oid_base = ['1.3.6.1.2.1.2.2.1.1.',  # ifIndex
                    '1.3.6.1.2.1.2.2.1.2.',  # ifDescr
                    '1.3.6.1.2.1.2.2.1.3.',  # ifType
                    '1.3.6.1.2.1.2.2.1.4.',  # IfMtu
                    '1.3.6.1.2.1.2.2.1.5.',  # ifSpeed
                    '1.3.6.1.2.1.2.2.1.6.',  # ifPhysAddress
                    '1.3.6.1.2.1.2.2.1.7.',  # ifAdminStatus
                    '1.3.6.1.2.1.2.2.1.8.',  # ifOperStatus
                    '1.3.6.1.2.1.2.2.1.9.',  # ifLastChange
                    '1.3.6.1.2.1.2.2.1.10.',  # ifInOctets
                    '1.3.6.1.2.1.2.2.1.11.',  # ifInUcastPkts
                    '1.3.6.1.2.1.2.2.1.12.',  # ifInNUcastPkts
                    '1.3.6.1.2.1.2.2.1.13.',  # ifInDiscards
                    '1.3.6.1.2.1.2.2.1.14.',  # ifInErrors
                    '1.3.6.1.2.1.2.2.1.15.',  # ifInUnknownProtos
                    '1.3.6.1.2.1.2.2.1.16.',  # ifOutOctets
                    '1.3.6.1.2.1.2.2.1.17.',  # ifOutUcastPkts
                    '1.3.6.1.2.1.2.2.1.18.',  # ifOutNUcastPkts
                    '1.3.6.1.2.1.2.2.1.19.',  # ifOutDiscards
                    '1.3.6.1.2.1.2.2.1.20.',  # ifOutErrors
                    '1.3.6.1.2.1.2.2.1.21.',  # ifOUtQLen
                    '1.3.6.1.2.1.2.2.1.22.',  # ifSpecific
                    # High capacity counters
                    # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.2.1.31.1.1.1.6
                    '1.3.6.1.2.1.31.1.1.1.6.',  # ifHCInOctets
                    '1.3.6.1.2.1.31.1.1.1.7.',  # ifHCInOctets
                    '1.3.6.1.2.1.31.1.1.1.10.',  # ifHCOutOctets
                    '1.3.6.1.2.1.31.1.1.1.11.']  # ifHCOutOctets

        while True:
            try:
                for interface in snmpif.interfaces():
                    oid_args = [str(b + interface) for b in oid_base]
                    error_indication, error_status, error_index, var_binds = cmd_gen.getCmd(
                        snmpif.security_object(), snmpif.transport(), *oid_args, lookupNames=True, lookupValues=True)
                    if error_indication:
                        logging.error(error_indication)
                    elif error_status:
                        logging.error(error_status)
                    else:
                        handle_output(var_binds, snmpif.destination())

            except Exception as ex:  # catch *all* exceptions
                logging.exception("Exception with getCmd to %s:%s %s" % (snmpif.destination(), snmpif.port, ex))
                time.sleep(float(snmpif.snmpinterval()))
                continue

            time.sleep(float(snmpif.snmpinterval()))

    except Exception as ex:
        logging.exception("Exception in run: %s" % ex)
        sys.exit(1)


def handle_output(response_object, destination):
    try:
        handler = InterfaceResponseHandler()
        handler(response_object, destination)
        sys.stdout.flush()
    except Exception as ex:
        logging.exception("Looks like an error handle the response output %s" % ex)


def do_validate():
    try:
        snmpif.read_config()
        if not snmpif.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception as ex:
        logging.exception("Exception validating %s" % ex)
        sys.exit(1)


def do_scheme():
    print snmpif.scheme()


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
        else:
            usage()
    else:
        do_run()
    sys.exit(0)
