"""
SNMP Interface Modular Input
"""

import logging
import xml.dom.minidom
import xml.sax.saxutils
import time
import os
import sys

SPLUNK_HOME = os.environ.get("SPLUNK_HOME")

# dynamically load in any eggs in /etc/apps/snmp_ta/bin
egg_dir = SPLUNK_HOME + "/etc/apps/snmp_ta/bin/"
for filename in os.listdir(egg_dir):
    if filename.endswith(".egg"):
        sys.path.append(egg_dir + filename)

# directory of the custom MIB eggs
mib_egg_dir = SPLUNK_HOME + "/etc/apps/snmp_ta/bin/mibs"
sys.path.append(mib_egg_dir)
for filename in os.listdir(mib_egg_dir):
    if filename.endswith(".egg"):
        sys.path.append(mib_egg_dir + "/" + filename)

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.smi import builder
from pysnmp.smi import view
from SnmpStanza import *

snmpif = SnmpIf()


def get_cmd_gen(mib_names_args):
    global mib_view
    # load in custom MIBS
    cmd_gen = cmdgen.CommandGenerator()
    mib_builder = cmd_gen.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
    mib_sources = (builder.DirMibSource(mib_egg_dir),)
    for mibfile in os.listdir(mib_egg_dir):
        if mibfile.endswith(".egg"):
            mib_sources = mib_sources + (builder.ZipMibSource(mibfile),)
    mib_sources = mib_builder.getMibSources() + mib_sources
    mib_builder.setMibSources(*mib_sources)
    if mib_names_args:
        mib_builder.loadModules(*mib_names_args)
    mib_view = view.MibViewController(mib_builder)
    return cmd_gen, mib_view


def do_run():
    snmpif.read_config()

    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                h.setFormatter(logging.Formatter(
                    '%(levelname)s %(message)s snmp-iface:{0} snmp_destination:{1} snmp_port:{2}'.format(
                        snmpif.name(), snmpif.destination(), snmpif.port())))

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        logging.error("Couldn't update logging templates: %s host:'" % str(e))

    # MIBs to load
    mib_names_args = ['IF-MIB']

    global mib_view
    cmd_gen, mib_view = get_cmd_gen(mib_names_args)

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
                    '1.3.6.1.2.1.31.1.1.1.10.']  # ifHCOutOctets

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

            except:  # catch *all* exceptions
                logging.exception("Exception with getCmd to %s:%s" % (snmpif.destination(), snmpif.port))
                time.sleep(float(snmpif.snmpinterval()))
                continue

            time.sleep(float(snmpif.snmpinterval()))

    except:
        logging.exception("Exception in run")
        sys.exit(1)


def handle_output(response_object, destination):
    try:
        from responsehandlers import InterfaceResponseHandler

        handler = InterfaceResponseHandler()
        handler(response_object, destination)
        sys.stdout.flush()
    except Exception:
        logging.exception("Looks like an error handle the response output")


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
