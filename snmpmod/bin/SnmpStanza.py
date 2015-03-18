import logging
import sys
import xml.dom.minidom

from pysnmp.entity.rfc3413.oneliner import cmdgen

from snmputils import print_validation_error


__author__ = 'John'


class SnmpStanza():
    """
    A class to represent a SNMP stanza in inputs.conf
    """

    def __init__(self):
        self.conf = {}

    def scheme(self):
        return "XML Scheme here.  Some way of extending it..."

    def read_config(self):
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
                    self.conf["name"] = stanza_name

                    params = stanza.getElementsByTagName("param")
                    for param in params:
                        param_name = param.getAttribute("name")
                        logging.debug("XML: found param '%s'" % param_name)
                        if param_name and param.firstChild and \
                                        param.firstChild.nodeType == param.firstChild.TEXT_NODE:
                            data = param.firstChild.data
                            self.conf[param_name] = data
                            logging.debug("XML: '%s' -> '%s'" % (param_name, data))

        checkpnt_node = root.getElementsByTagName("checkpoint_dir")[0]
        if (checkpnt_node and checkpnt_node.firstChild and
                    checkpnt_node.firstChild.nodeType == checkpnt_node.firstChild.TEXT_NODE):
            self.conf["checkpoint_dir"] = checkpnt_node.firstChild.data

        if not self.conf:
            raise Exception("Invalid configuration received from Splunk.")

    def port(self):
        return int(self.conf.get("port", 161))

    def destination(self):
        return self.conf.get("destination")

    def snmpinterval(self):
        return self.conf.get("snmpinterfal", 60)

    def name(self):
        return self.conf.get("name")

    def ipv6(self):
        return int(self.conf.get("ipv6", 0))

    def transport(self):
        """
        Get the SNMP transport taking into consideration ipv4/ipv6
        :return: SNMP transport
        """
        if self.ipv6():
            transport = cmdgen.Udp6TransportTarget((self.destination(), self.port()))
        else:
            transport = cmdgen.UdpTransportTarget((self.destination(), self.port()))
        return transport

    def security_object(self):
        """
        Get the SNMP security object from the configuration, taking into consideration the SNMP version

        :return: security object
        """
        # snmp 1 and 2C params
        snmp_version = self.conf.get("snmp_version", "2C")

        if snmp_version == "3":
            v3_security_name = self.conf.get("v3_securityName", "")
            v3_auth_key = self.conf.get("v3_authKey", None)
            v3_priv_key = self.conf.get("v3_privKey", None)
            v3_auth_protocol_str = self.conf.get("v3_authProtocol", "usmHMACMD5AuthProtocol")
            v3_priv_protocol_str = self.conf.get("v3_privProtocol", "usmDESPrivProtocol")

            v3_auth_protocol = {
                'usmHMACMD5AuthProtocol': cmdgen.usmHMACMD5AuthProtocol,
                'usmHMACSHAAuthProtocol': cmdgen.usmHMACSHAAuthProtocol,
                'usmNoAuthProtocol': cmdgen.usmNoAuthProtocol
            }.get(v3_auth_protocol_str)
            v3_priv_protocol = {
                'usmDESPrivProtocol': cmdgen.usmDESPrivProtocol,
                'usm3DESEDEPrivProtocol': cmdgen.usm3DESEDEPrivProtocol,
                'usmAesCfb128Protocol': cmdgen.usmAesCfb128Protocol,
                'usmAesCfb192Protocol': cmdgen.usmAesCfb192Protocol,
                'usmAesCfb256Protocol': cmdgen.usmAesCfb256Protocol,
                'usmNoPrivProtocol': cmdgen.usmNoPrivProtocol,
            }.get(v3_priv_protocol_str)

            security_object = cmdgen.UsmUserData(v3_security_name, authKey=v3_auth_key, privKey=v3_priv_key,
                                                 authProtocol=v3_auth_protocol, privProtocol=v3_priv_protocol)
        else:
            communitystring = self.conf.get("communitystring", "public")
            mp_model_val = 1
            if snmp_version == "1":
                mp_model_val = 0
            security_object = cmdgen.CommunityData(communitystring, mpModel=mp_model_val)

        return security_object

    def is_valid(self):
        valid = True

        if self.port() is None or int(self.port()) < 1:
            print_validation_error("Port value must be a positive integer")
            valid = False
        if self.snmpinterval() is None or int(self.snmpinterval()) < 1:
            print_validation_error("SNMP Polling interval must be a positive integer")
            valid = False
        if self.destination() is None:
            print_validation_error("Destination must be present")
            valid = False

        # TODO Validate security options??

        return valid


class SnmpIf(SnmpStanza):
    def __init__(self):
        SnmpStanza.__init__(self)

    def interfaces(self):
        interfaces_str = self.conf.get("interfaces", None)
        if interfaces_str is None:
            return None
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
