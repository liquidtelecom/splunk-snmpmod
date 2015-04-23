[snmpif://<name>]
*IP or hostname of the device you would like to query
destination= <value>

*Whether or not this is an IP version 6 address. Defaults to false.
ipv6= <value>

*The SNMP port. Defaults to 161
port= <value>

*The SNMP Version , 1 / 2C / 3 . Defaults to 2C
snmp_version= <value>

*1 or more interface numbers
interfaces = <value>

*Community String used for SNMP version 1 and 2C authentication.Defaults to "public"
communitystring= <value>

*SNMPv3 USM username
v3_securityName= <value>

*SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter
v3_authKey= <value>

*SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.
v3_privKey= <value>

*may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol
v3_authProtocol= <value>

*may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol
v3_privProtocol= <value>

*How often to run the SNMP query (in seconds). Defaults to 60 seconds
snmpinterval= <value>

*Python classname of custom response handler
response_handler= <value>

*Response Handler arguments string ,  key=value,key2=value2
response_handler_args= <value>

[ipsla://<name>]
*IP or hostname of the device you would like to query
destination= <value>

*Whether or not this is an IP version 6 address. Defaults to false.
ipv6= <value>

*The SNMP port. Defaults to 161
port= <value>

*The SNMP Version , 1 / 2C / 3 . Defaults to 2C
snmp_version= <value>

*1 or more operations
operations = <value>

*Community String used for SNMP version 1 and 2C authentication.Defaults to "public"
communitystring= <value>

*SNMPv3 USM username
v3_securityName= <value>

*SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter
v3_authKey= <value>

*SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.
v3_privKey= <value>

*may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol
v3_authProtocol= <value>

*may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol
v3_privProtocol= <value>

*How often to run the SNMP query (in seconds). Defaults to 60 seconds
snmpinterval= <value>
