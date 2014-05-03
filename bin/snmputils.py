import xml
from pysnmp.entity.rfc3413.oneliner import cmdgen


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
    print "<error><message>%s</message></error>" % xml.sax.saxutils.escape(s)

