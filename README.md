SnmpMod
=======

Splunk SNMP Modular Input

This project was originally based on [SplunkModularInputsPythonFramework](https://github.com/damiendallimore/SplunkModularInputsPythonFramework).
I have taken the SNMP modular input, refactored the python code to be more re-usable and added an extra stanza for polling interfaces.

Deployment
==========

    cd $SPLUNK_HOME/etc/apps
    git clone https://github.com/oxo42/snmpmod.git
    mkdir local
	vim local/inputs.conf

*Need a section on pycrypto for SNMP 3*

snmp Stanza
===========

snmpif Stanza
=============

    [snmpif://hostname]
    destination = hostname
    snmp_version = 3
    v3_securityName = username
    v3_authKey = password
    snmpinterval = 60
    interfaces = 1,5,8,9
    index = network
    sourcetype = snmpif


Response Handlers
=================