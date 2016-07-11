# This file contains possible attributes and values you can use to configure inputs for SNMP modular input
# -*- mode: ini -*-
# vim: set ft=dosini:

[snmpif://<name>]
destination= <value>
* IP or hostname of the device you would like to query

ipv6= <value>
* Whether or not this is an IP version 6 address. Defaults to false.

port= <value>
* The SNMP port. Defaults to 161

* The SNMP Version , 1 / 2C / 3 . Defaults to 2C
snmp_version= <value>

interfaces = <value>
* 1 or more interface numbers

communitystring= <value>
* Community String used for SNMP version 1 and 2C authentication.Defaults to "public"

v3_securityName= <value>
* SNMPv3 USM username

v3_authKey= <value>
* SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter

v3_privKey= <value>
* SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.

v3_authProtocol= <value>
* may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol

v3_privProtocol= <value>
* may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol

snmpinterval= <value>
* How often to run the SNMP query (in seconds). Defaults to 60 seconds

[ipsla://<name>]
destination= <value>
* IP or hostname of the device you would like to query

ipv6= <value>
* Whether or not this is an IP version 6 address. Defaults to false.

port= <value>
* The SNMP port. Defaults to 161

snmp_version= <value>
* The SNMP Version , 1 / 2C / 3 . Defaults to 2C

operations = <value>
* 1 or more operations

communitystring= <value>
* Community String used for SNMP version 1 and 2C authentication.Defaults to "public"

v3_securityName= <value>
* SNMPv3 USM username

v3_authKey= <value>
* SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter

v3_privKey= <value>
* SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.

v3_authProtocol= <value>
* may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol

v3_privProtocol= <value>
* may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol

snmpinterval= <value>
* How often to run the SNMP query (in seconds). Defaults to 60 seconds

[qos://name]
destination= <value>
* IP or hostname of the device you would like to query

ipv6= <value>
* Whether or not this is an IP version 6 address. Defaults to false.

port= <value>
* The SNMP port. Defaults to 161

snmp_version= <value>
* The SNMP Version , 1 / 2C / 3 . Defaults to 2C

interfaces = <value>
* 1 or more SNMP interfaces to gather statistics for

stats = <value>
* Comma separated list of statistics to pull for each interface map.  Valid options are
* prePolicyBitRate (1.3.6.1.4.1.9.9.166.1.15.1.1.7)
* postPolicyBitRate (1.3.6.1.4.1.9.9.166.1.15.1.1.11)

communitystring= <value>
* Community String used for SNMP version 1 and 2C authentication.Defaults to "public"

v3_securityName= <value>
* SNMPv3 USM username

v3_authKey= <value>
* SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter

v3_privKey= <value>
* SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.

v3_authProtocol= <value>
* may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol

v3_privProtocol= <value>
* may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol

snmpinterval= <value>
* How often to run the SNMP query (in seconds). Defaults to 60 seconds


[snmpEkinops://name]
destination= <value>
* IP or hostname of the device you would like to query

ipv6= <value>
* Whether or not this is an IP version 6 address. Defaults to false.

port= <value>
* The SNMP port. Defaults to 161

* The SNMP Version , 1 / 2C / 3 . Defaults to 2C
snmp_version= <value>

interfaces = <value>
* 1 or more interface numbers

communitystring= <value>
* Community String used for SNMP version 1 and 2C authentication.Defaults to "public"

v3_securityName= <value>
* SNMPv3 USM username

v3_authKey= <value>
* SNMPv3 secret authorization key used within USM for SNMP PDU authorization. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) to take effect. Default hashing method may be changed by means of further authProtocol parameter

v3_privKey= <value>
* SNMPv3 secret encryption key used within USM for SNMP PDU encryption. Setting it to a non-empty value implies MD5-based PDU authentication (defaults to usmHMACMD5AuthProtocol) and DES-based encryption (defaults to usmDESPrivProtocol) to take effect. Default hashing and/or encryption methods may be changed by means of further authProtocol and/or privProtocol parameters.

v3_authProtocol= <value>
* may be used to specify non-default hash function algorithm. Possible values include usmHMACMD5AuthProtocol (default) / usmHMACSHAAuthProtocol / usmNoAuthProtocol

v3_privProtocol= <value>
* may be used to specify non-default ciphering algorithm. Possible values include usmDESPrivProtocol (default) / usmAesCfb128Protocol / usm3DESEDEPrivProtocol / usmAesCfb192Protocol / usmAesCfb256Protocol / usmNoPrivProtocol

snmpinterval= <value>
* How often to run the SNMP query (in seconds). Defaults to 60 seconds

