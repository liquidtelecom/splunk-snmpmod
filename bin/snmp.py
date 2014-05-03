"""
Modular Input Script

Copyright (C) 2012 Splunk, Inc.
All Rights Reserved

"""

import logging
import time
import threading
import os
import sys
import xml.dom.minidom
import xml.sax.saxutils

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

RESPONSE_HANDLER_INSTANCE = None

# Have to load the MIBs before importing these
from pysnmp.carrier.asynsock.dispatch import AsynsockDispatcher
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import engine, config
from pyasn1.codec.ber import decoder
from pysnmp.proto import api
from pysnmp.smi import builder
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.smi import view
from snmputils import *

# Initialize the root logger with a StreamHandler and a format message:
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(message)s')

SCHEME = """<scheme>
    <title>SNMP</title>
    <description>SNMP input to poll attribute values and catch traps</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>false</use_single_instance>

    <endpoint>
        <args>    
            <arg name="name">
                <title>SNMP Input Name</title>
                <description>Name of this SNMP input</description>
            </arg>  
            <arg name="snmp_mode">
                <title>SNMP Mode</title>
                <description>Whether or not this stanza is for polling attributes or listening for traps</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
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
            <arg name="object_names">
                <title>Object Names</title>
                <description>
                    1 or more Objects Names , comma delimited , in either textual
                    (iso.org.dod.internet.mgmt.mib-2.system.sysDescr.0) or numerical(1.3.6.1.2.1.1.3.0) format
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
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
            <arg name="do_bulk_get">
                <title>Perform GET BULK</title>
                <description>
                    Whether or not to perform an SNMP GET BULK operation.This will retrieve all the object attributes in
                    the sub tree of the declared OIDs.Be aware of potential performance issues,
                    http://www.net-snmp.org/wiki/index.php/GETBULK. Defaults to false
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="split_bulk_output">
                <title>Split Bulk Results</title>
                <description>
                    Whether or not to split up bulk output into individual events. Defaults to false.
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="non_repeaters">
                <title>Non Repeaters (for GET BULK)</title>
                <description>
                    The number of objects that are only expected to return a single GETNEXT instance, not multiple
                    instances. Managers frequently request the value of sysUpTime and only want that instance plus a
                    list of other objects.Defaults to 0
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="max_repetitions">
                <title>Max Repetitions (for GET BULK)</title>
                <description>
                    The number of objects that should be returned for all the repeating OIDs. Agent's must truncate the
                    list to something shorter if it won't fit within the max-message size supported by the command
                    generator or the agent.Defaults to 25
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="listen_traps">
                <title>Listen for TRAP messages</title>
                <description>Whether or not to listen for TRAP messages</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="trap_port">
                <title>TRAP listener port</title>
                <description>
                    TRAP listener port. Defaults to 162.Ensure that you have the necessary OS user permissions
                    for port values 0-1024
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="trap_host">
                <title>TRAP listener host</title>
                <description>TRAP listener host. Defaults to localhost</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="mib_names">
                <title>MIB Names</title>
                <description>
                    Comma delimited list of MIB names to be applied that you have deployed in the snmp_ta/bin/mibs
                    directory as a Python egg ie: IF-MIB,DNS-SERVER-MIB,BRIDGE-MIB
                </description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="response_handler">
                <title>Response Handler</title>
                <description>Python classname of custom response handler</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
            <arg name="response_handler_args">
                <title>Response Handler Arguments</title>
                <description>Response Handler arguments string: key=value,key2=value2</description>
                <required_on_edit>false</required_on_edit>
                <required_on_create>false</required_on_create>
            </arg>
        </args>
    </endpoint>
</scheme>
"""


def do_validate():
    try:
        config = get_input_config()

        port = config.get("port")
        trap_port = config.get("trap_port")
        snmpinterval = config.get("snmpinterval")
        max_repetitions = config.get("max_repetitions")
        non_repeaters = config.get("non_repeaters")

        validation_failed = False

        if not port is None and int(port) < 1:
            print_validation_error("Port value must be a positive integer")
            validation_failed = True
        if not trap_port is None and int(trap_port) < 1:
            print_validation_error("Trap port value must be a positive integer")
            validation_failed = True
        if not non_repeaters is None and int(non_repeaters) < 0:
            print_validation_error("Non Repeaters value must be zero or a positive integer")
            validation_failed = True
        if not max_repetitions is None and int(max_repetitions) < 0:
            print_validation_error("Max Repetitions value must be zero or a positive integer")
            validation_failed = True
        if not snmpinterval is None and int(snmpinterval) < 1:
            print_validation_error("SNMP Polling interval must be a positive integer")
            validation_failed = True
        if validation_failed:
            sys.exit(2)

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        logging.error("Exception getting config: %s" % str(e))
        sys.exit(1)


def v3trap_callback(snmp_engine, state_reference, context_engine_id, context_name, var_binds, cb_ctx):
    try:
        trap_metadata = ""
        server = ""
        (transport_domain, transport_address) = snmp_engine.msgAndPduDsp.getTransportInfo(state_reference)
        try:
            server = "%s" % transport_address
            trap_metadata += 'notification_from_address = "%s" ' % transport_address
            trap_metadata += 'notification_from_domain = "%s" ' % transport_domain
        except:  # catch *all* exceptions
            e = sys.exc_info()[1]
            logging.error("Exception resolving source address/domain of the trap: %s" % str(e))

        try:
            trap_metadata += 'context_engine_id = "%s" ' % (context_engine_id.prettyPrint())
            trap_metadata += 'context_name = "%s" ' % (context_name.prettyPrint())
        except:  # catch *all* exceptions
            e = sys.exc_info()[1]
            logging.error("Exception resolving context of the trap: %s" % str(e))

        handle_output(var_binds, server, from_trap=True, trap_metadata=trap_metadata)

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        logging.error("Exception receiving trap %s" % str(e))


def trap_callback(transportDispatcher, transportDomain, transportAddress, wholeMsg):
    try:
        while wholeMsg:
            msgVer = int(api.decodeMessageVersion(wholeMsg))
            if msgVer in api.protoModules:
                pMod = api.protoModules[msgVer]
            else:
                logging.error('Receiving trap , unsupported SNMP version %s' % msgVer)
                return
            reqMsg, wholeMsg = decoder.decode(wholeMsg, asn1Spec=pMod.Message(), )

            reqPDU = pMod.apiMessage.getPDU(reqMsg)

            trap_metadata = ""
            server = ""
            try:
                trap_metadata += 'notification_from_address = "%s" ' % (transportAddress)
                trap_metadata += 'notification_from_domain = "%s" ' % (transportDomain)
                server = "%s" % transportAddress
            except:  # catch *all* exceptions
                e = sys.exc_info()[1]
                logging.error("Exception resolving source address/domain of the trap: %s" % str(e))

            if reqPDU.isSameTypeWith(pMod.TrapPDU()):
                if msgVer == api.protoVersion1:
                    if server == "":
                        server = pMod.apiTrapPDU.getAgentAddr(reqPDU).prettyPrint()

                    trap_metadata += 'notification_enterprise = "%s" ' % (
                        pMod.apiTrapPDU.getEnterprise(reqPDU).prettyPrint())
                    trap_metadata += 'notification_agent_address = "%s" ' % (
                        pMod.apiTrapPDU.getAgentAddr(reqPDU).prettyPrint())
                    trap_metadata += 'notification_generic_trap = "%s" ' % (
                        pMod.apiTrapPDU.getGenericTrap(reqPDU).prettyPrint())
                    trap_metadata += 'notification_specific_trap = "%s" ' % (
                        pMod.apiTrapPDU.getSpecificTrap(reqPDU).prettyPrint())
                    trap_metadata += 'notification_uptime = "%s" ' % (
                        pMod.apiTrapPDU.getTimeStamp(reqPDU).prettyPrint())

                    varBinds = pMod.apiTrapPDU.getVarBindList(reqPDU)
                else:
                    varBinds = pMod.apiPDU.getVarBindList(reqPDU)

            handle_output(varBinds, server, from_trap=True, trap_metadata=trap_metadata)

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        logging.error("Exception receiving trap %s" % str(e))

    return wholeMsg


def do_run():
    conf = get_input_config()
    # params
    snmp_mode = conf.get("snmp_mode", "")
    destination = conf.get("destination")
    port = int(conf.get("port", 161))
    snmpinterval = int(conf.get("snmpinterval", 60))
    ipv6 = int(conf.get("ipv6", 0))

    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                h.setFormatter(logging.Formatter(
                    '%(levelname)s %(message)s snmp_stanza:{0} snmp_destination:{1} snmp_port:{2}'.format(
                        conf.get("name"), destination, port)))

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        logging.error("Couldn't update logging templates: %s host:'" % str(e))

    response_handler_args = {}
    response_handler_args_str = conf.get("response_handler_args")
    if not response_handler_args_str is None:
        delimiter = ','
        response_handler_args = dict((k.strip(), v.strip()) for k, v in
                                     (item.split('=') for item in response_handler_args_str.split(delimiter)))

    response_handler = conf.get("response_handler", "DefaultResponseHandler")
    module = __import__("responsehandlers")
    class_ = getattr(module, response_handler)

    global RESPONSE_HANDLER_INSTANCE
    RESPONSE_HANDLER_INSTANCE = class_(**response_handler_args)

    # snmp 1 and 2C params
    snmp_version = conf.get("snmp_version", "2C")

    v3_security_name = conf.get("v3_securityName", "")
    v3_auth_key = conf.get("v3_authKey", None)
    v3_priv_key = conf.get("v3_privKey", None)
    v3_auth_protocol_str = conf.get("v3_authProtocol", "usmHMACMD5AuthProtocol")
    v3_priv_protocol_str = conf.get("v3_privProtocol", "usmDESPrivProtocol")

    v3_auth_protocol = get_v3_auth_protocol(v3_auth_protocol_str)
    v3_priv_protocol = get_v3_priv_protocol(v3_priv_protocol_str)

    object_names = conf.get("object_names")
    oid_args = None
    if not object_names is None:
        oid_args = [str(x.strip()) for x in object_names.split(',')]

    # GET BULK params
    do_bulk = int(conf.get("do_bulk_get", 0))
    split_bulk_output = int(conf.get("split_bulk_output", 0))
    non_repeaters = int(conf.get("non_repeaters", 0))
    max_repetitions = int(conf.get("max_repetitions", 25))

    # TRAP listener params
    listen_traps = int(conf.get("listen_traps", 0))
    # some backwards compatibility gymnastics
    if snmp_mode == 'traps':
        listen_traps = 1

    trap_port = int(conf.get("trap_port", 162))
    trap_host = conf.get("trap_host", "localhost")

    # MIBs to load
    mib_names = conf.get("mib_names")
    mib_names_args = None
    if not mib_names is None:
        mib_names_args = map(str, mib_names.split(","))
        # trim any whitespace using a list comprehension
        mib_names_args = [x.strip(' ') for x in mib_names_args]

    # load in custom MIBS
    cmd_gen = cmdgen.CommandGenerator()

    mib_builder = cmd_gen.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder

    mibSources = (builder.DirMibSource(mib_egg_dir),)

    for mibfile in os.listdir(mib_egg_dir):
        if mibfile.endswith(".egg"):
            mibSources = mibSources + (builder.ZipMibSource(mibfile),)

    mibSources = mib_builder.getMibSources() + mibSources
    mib_builder.setMibSources(*mibSources)

    if mib_names_args:
        mib_builder.loadModules(*mib_names_args)

    global mib_view
    mib_view = view.MibViewController(mib_builder)

    if listen_traps:
        if snmp_version == "1" or snmp_version == "2C":
            trapThread = TrapThread(trap_port, trap_host, ipv6)
            trapThread.start()
        if snmp_version == "3":
            trapThread = V3TrapThread(trap_port, trap_host, ipv6, v3_security_name, v3_auth_key, v3_auth_protocol,
                                      v3_priv_key, v3_priv_protocol)
            trapThread.start()

    if not (object_names is None) and not (destination is None):
        try:
            transport = get_transport(conf)
            security_object = get_security_object(conf)

            while True:
                if do_bulk and not snmp_version == "1":
                    try:
                        errorIndication, errorStatus, errorIndex, varBindTable = cmd_gen.bulkCmd(
                            security_object,
                            transport,
                            non_repeaters, max_repetitions,
                            *oid_args, lookupNames=True, lookupValues=True)
                    except:  # catch *all* exceptions
                        e = sys.exc_info()[1]
                        logging.error("Exception with bulkCmd to %s:%s: %s" % (destination, port, str(e)))
                        time.sleep(float(snmpinterval))
                        continue
                else:
                    try:
                        errorIndication, errorStatus, errorIndex, varBinds = cmd_gen.getCmd(
                            security_object,
                            transport,
                            *oid_args, lookupNames=True, lookupValues=True)
                    except:  # catch *all* exceptions
                        e = sys.exc_info()[1]
                        logging.error("Exception with getCmd to %s:%s: %s" % (destination, port, str(e)))
                        time.sleep(float(snmpinterval))
                        continue

                if errorIndication:
                    logging.error(errorIndication)
                elif errorStatus:
                    logging.error(errorStatus)
                else:
                    if do_bulk:
                        handle_output(varBindTable, destination, table=True, split_bulk_output=split_bulk_output)
                    else:
                        handle_output(varBinds, destination, table=False, split_bulk_output=split_bulk_output)

                time.sleep(float(snmpinterval))

        except:  # catch *all* exceptions
            e = sys.exc_info()[1]
            logging.error("Looks like an error: %s" % str(e))
            sys.exit(1)


class TrapThread(threading.Thread):
    def __init__(self, port, host, ipv6):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host
        self.ipv6 = ipv6

    def run(self):

        transportDispatcher = AsynsockDispatcher()
        transportDispatcher.registerRecvCbFun(trap_callback)
        if self.ipv6:
            transport = udp.Udp6SocketTransport()
            domainName = udp6.domainName
        else:
            transport = udp.UdpSocketTransport()
            domainName = udp.domainName

        try:
            transportDispatcher.registerTransport(domainName, transport.openServerMode((self.host, self.port)))

            transportDispatcher.jobStarted(1)
            # Dispatcher will never finish as job#1 never reaches zero
            transportDispatcher.runDispatcher()
        except:  # catch *all* exceptions
            e = sys.exc_info()[1]
            transportDispatcher.closeDispatcher()
            logging.error("Failed to register transport and run dispatcher: %s" % str(e))
            sys.exit(1)


class V3TrapThread(threading.Thread):
    def __init__(self, port, host, ipv6, user, auth_key, auth_proto, priv_key, priv_proto):
        threading.Thread.__init__(self)
        self.port = port
        self.host = host
        self.ipv6 = ipv6
        self.user = user
        self.auth_key = auth_key
        self.auth_proto = auth_proto
        self.priv_key = priv_key
        self.priv_proto = priv_proto

    def run(self):

        snmpEngine = engine.SnmpEngine()

        if self.ipv6:
            domainName = udp6.domainName
            config.addSocketTransport(snmpEngine, domainName,
                                      udp6.Udp6Transport().openServerMode((self.host, self.port)))
        else:
            domainName = udp.domainName
            config.addSocketTransport(snmpEngine, domainName, udp.UdpTransport().openServerMode((self.host, self.port)))

        config.addV3User(snmpEngine, self.user, self.auth_proto, self.auth_key, self.priv_proto, self.priv_key)

        # Register SNMP Application at the SNMP engine
        ntfrcv.NotificationReceiver(snmpEngine, v3trap_callback)

        snmpEngine.transportDispatcher.jobStarted(1)  # this job would never finish

        # Run I/O dispatcher which would receive queries and send confirmations
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except:  # catch *all* exceptions
            e = sys.exc_info()[1]
            snmpEngine.transportDispatcher.closeDispatcher()
            logging.error("Looks like an error: %s" % str(e))
            sys.exit(1)


def handle_output(response_object, destination, table=False, from_trap=False, trap_metadata=None,
                  split_bulk_output=False):
    try:
        if destination == "":
            destination = os.environ.get("SPLUNK_SERVER")

        RESPONSE_HANDLER_INSTANCE(response_object, destination, table=table, from_trap=from_trap,
                                  trap_metadata=trap_metadata, split_bulk_output=split_bulk_output, mib_view=mib_view)
        sys.stdout.flush()
    except:
        e = sys.exc_info()[1]
        logging.error("Looks like an error handle the response output: %s" % str(e))


def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    logging.error("Incorrect Program Usage")
    sys.exit(2)


def do_scheme():
    print SCHEME


def get_input_config():
    """
    read XML configuration passed from splunkd, need to refactor to support single instance mode
    :return:
    """
    conf = {}

    try:
        # read everything from stdin
        config_str = sys.stdin.read()

        # parse the config XML
        doc = xml.dom.minidom.parseString(config_str)
        root = doc.documentElement
        conf_node = root.getElementsByTagName("configuration")[0]
        if conf_node:
            logging.debug("XML: found configuration")
            stanza = conf_node.getElementsByTagName("stanza")[0]
            if stanza:
                stanza_name = stanza.getAttribute("name")
                if stanza_name:
                    logging.debug("XML: found stanza " + stanza_name)
                    conf["name"] = stanza_name
                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                                        param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            conf[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if checkpnt_node and checkpnt_node.firstChild and \
                        checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE:
            conf["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not conf:
            raise Exception("Invalid configuration received from Splunk.")

    except:  # catch *all* exceptions
        e = sys.exc_info()[1]
        raise Exception("Error getting Splunk configuration via STDIN: %s" % str(e))

    return conf


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
