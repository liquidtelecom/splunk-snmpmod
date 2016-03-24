import string
import os
import sys

splunk_home = os.environ.get("SPLUNK_HOME")
egg_dir = os.path.join(splunk_home, "etc", "apps", "snmpmod", "bin")

# directory of the custom MIB eggs
mib_egg_dir = os.path.join(egg_dir, "mibs")


def load_eggs():
    # dynamically load in any eggs in $SPLUNK_HOME/etc/apps/mod/bin
    for filename in os.listdir(egg_dir):
        if filename.endswith(".egg"):
            sys.path.append(os.path.join(egg_dir, filename))

    sys.path.append(mib_egg_dir)
    for filename in os.listdir(mib_egg_dir):
        if filename.endswith(".egg"):
            sys.path.append(os.path.join(mib_egg_dir, filename))


load_eggs()
from pysnmp.entity.rfc3413.oneliner import cmdgen
# noinspection PyUnresolvedReferences
from pysnmp.proto.rfc1905 import NoSuchInstance
import logging

logging_format_string = '%(levelname)s file="%(filename)s" line=%(lineno)d %(message)s'


def get_cmd_gen():
    cmd_gen = cmdgen.CommandGenerator()
    return cmd_gen


class SnmpException(Exception):
    def __init__(self, msg, error_type):
        self.error_type = error_type
        self.msg = msg


def walk_oids(cmd_gen, security_object, transport, oids):
    """
    Takes a list of oids, runs them against the configured target returning the result table or throws and exception
    :param cmd_gen: SNMP cmd_gen
    :param security_object: SNMP security object
    :param transport: SNMP transport
    :param oids oids to poll
    :returns Tuple of (e_indication, e_status, e_index, res)
    """

    snmp_result = cmd_gen.nextCmd(security_object, transport, *oids)
    error_indication, error_status, error_index, var_binds_table = snmp_result

    if error_indication:
        raise SnmpException(error_indication, 'snmp_engine')
    elif error_status:
        msg = '%s at %s' % (error_status.prettyPrint(),
                            error_index and var_binds_table[int(error_index) - 1][0] or '?')
        raise SnmpException(msg, 'pdu')

    return var_binds_table


def query_oids(cmd_gen, security_object, transport, oids):
    """
    Takes a list of oids and runs them against the target returning the results or throwing an exception
    :param cmd_gen: SNMP cmd_gen
    :param security_object: SNMP security object
    :param transport: SNMP transport
    :param oids oids to poll
    """
    # The difference between this and walk is query_oids expects an exact oid.  walk oids will take .4.5.1 and if
    # there's a single value under .4.5.1.0 it will report on that
    # I probably don't want to do a walk most of the time.  This shit is confusing :(

    snmp_result = cmd_gen.getCmd(security_object, transport, *oids)
    error_indication, error_status, error_index, var_binds_table = snmp_result

    if error_indication:
        logging.debug('error_indication=%s error_status=%s error_index=%s', error_indication, error_status, error_index)
        raise SnmpException(error_indication, 'snmp_engine')
    elif error_status:
        msg = '%s at %s' % (error_status.prettyPrint(),
                            error_index and var_binds_table[int(error_index) - 1][0] or '?')
        raise SnmpException(msg, 'pdu')

    return var_binds_table


def get_v3_auth_protocol(v3_auth_protocol_str):
    return {
        'usmHMACMD5AuthProtocol': cmdgen.usmHMACMD5AuthProtocol,
        'usmHMACSHAAuthProtocol': cmdgen.usmHMACSHAAuthProtocol,
        'usmNoAuthProtocol': cmdgen.usmNoAuthProtocol
    }.get(v3_auth_protocol_str, cmdgen.usmNoAuthProtocol)


def get_v3_priv_protocol(v3_priv_protocol_str):
    return {
        'usmDESPrivProtocol': cmdgen.usmDESPrivProtocol,
        'usm3DESEDEPrivProtocol': cmdgen.usm3DESEDEPrivProtocol,
        'usmAesCfb128Protocol': cmdgen.usmAesCfb128Protocol,
        'usmAesCfb192Protocol': cmdgen.usmAesCfb192Protocol,
        'usmAesCfb256Protocol': cmdgen.usmAesCfb256Protocol,
        'usmNoPrivProtocol': cmdgen.usmNoPrivProtocol,
    }.get(v3_priv_protocol_str, cmdgen.usmNoPrivProtocol)


def get_transport(conf):
    """
    Get the SNMP transport taking into consideration ipv4/ipv6
    :param conf:
    :return: SNMP transport
    """
    destination = conf.get("destination")
    port = int(conf.get("port", 161))
    ipv6 = int(conf.get("ipv6", 0))

    if ipv6:
        transport = cmdgen.Udp6TransportTarget((destination, port))
    else:
        transport = cmdgen.UdpTransportTarget((destination, port))
    return transport


def get_security_object(conf):
    """
    Get the SNMP security object from the configuration, taking into consideration the SNMP version

    :param conf: Configuration
    :return: security object
    """
    # snmp 1 and 2C params
    snmp_version = conf.get("snmp_version", "2C")

    if snmp_version == "3":
        v3_security_name = conf.get("v3_securityName", "")
        v3_auth_key = conf.get("v3_authKey", None)
        v3_priv_key = conf.get("v3_privKey", None)
        v3_auth_protocol_str = conf.get("v3_authProtocol", "usmHMACMD5AuthProtocol")
        v3_priv_protocol_str = conf.get("v3_privProtocol", "usmDESPrivProtocol")

        v3_auth_protocol = get_v3_auth_protocol(v3_auth_protocol_str)
        v3_priv_protocol = get_v3_priv_protocol(v3_priv_protocol_str)

        security_object = cmdgen.UsmUserData(v3_security_name, authKey=v3_auth_key, privKey=v3_priv_key,
                                             authProtocol=v3_auth_protocol, privProtocol=v3_priv_protocol)
    else:
        communitystring = conf.get("communitystring", "public")
        mp_model_val = 1
        if snmp_version == "1":
            mp_model_val = 0
        security_object = cmdgen.CommunityData(communitystring, mpModel=mp_model_val)

    return security_object


def print_validation_error(s):
    """
    Print validation error data to be consumed by Splunk
    :param s:
    :return:
    """
    print "<error><message>%s</message></error>" % encode_xml_text(s)


def splunk_escape(data):
    input_string = str(data)
    if input_string is None or input_string == '':
        return ""
    s = string.replace(input_string, "'", "")

    def should_escape():
        import re
        if re.search(r"\W+", s):
            return True
        else:
            return False

    if should_escape():
        return "\"%s\"" % s
    else:
        return s


# prints XML stream
def print_xml_single_instance_mode(server, event):
    print "<stream><event><data>%s</data><host>%s</host></event></stream>" % (
        encode_xml_text(event), server)


def encode_xml_text(text):
    text = text.replace("&", "&amp;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&apos;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", "")
    return text


def set_logger_format(name):
    # noinspection PyBroadException
    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                formatter = '%(levelname)s file="%(filename)s" line=%(lineno)d stanza="{0}" %(message)s'.format(name)
                h.setFormatter(logging.Formatter(formatter))

    except Exception:
        logging.exception("Couldn't update logging templates")


# prints XML stream
def print_xml_multi_instance_mode(server, event, stanza):
    print "<stream><event stanza=""%s""><data>%s</data><host>%s</host></event></stream>" % (
        stanza, encode_xml_text(event), server)


# prints simple stream
def print_simple(s):
    print "%s\n" % s


# HELPER FUNCTIONS

# prints XML stream
def print_xml_stream(s):
    print "<stream><event unbroken=\"1\"><data>%s</data><done/></event></stream>" % encode_xml_text(s)
