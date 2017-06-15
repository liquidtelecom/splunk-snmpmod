import logging
import sys
import xml.dom.minidom

from pysnmp.entity.rfc3413.oneliner import cmdgen

from snmputils import print_validation_error, splunk_escape

__author__ = 'John Oxley'


class SnmpStanza:
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

                    conf_dict = [(param, splunk_escape(self.conf[param]))
                                 for param in self.conf
                                 if param in ['destination', 'interfaces', 'operations']]

                    conf_str = ' '.join(['%s=%s' % nvp for nvp in conf_dict])
                    logging.info('action=configured stanza="%s" %s', self.conf['name'], conf_str)

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
        return self.conf.get("snmpinterval", 60)

    def name(self):
        return self.conf.get("name")

    def aliasSearchRegex(self):
        return self.conf.get("aliasSearchRegex", "")

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
            transport = cmdgen.UdpTransportTarget((self.destination(), self.port()), timeout=5, retries=1)
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
