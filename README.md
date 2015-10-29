SnmpMod
=======

[Release Notes](ReleaseNotes.md)

Deployment
==========

```shell
splunk install app snmpmod.spl -update 1 -auth admin:changeme
cd $SPLUNK_HOME/etc/apps/snmpmod
mkdir local
vim local/inputs.conf
```

SNMP v3
-------
If you are using SNMP version 3 , you have to obtain the [PyCrypto](https://www.dlitz.net/software/pycrypto/) package yourself:

As of Python 2.7.9, pip is included with the release.  Run

```shell
pip2 install pycrypto
```


* Windows
  * Copy the folder `C:\Python27\Lib\site-packages\Crypto` to `$SPLUNK_HOME\etc\apps\snmpmod\bin`
* Linux
  * `cp -Rv /usr/local/lib/python2.7/dist-packages/Crypto $SPLUNK_HOME/etc/apps/snmpmod/bin`

snmpif Stanza
=============

```ini
[snmpif://hostname]
destination = hostname
snmp_version = 3
v3_securityName = username
v3_authKey = password
snmpinterval = 300
interfaces = 1,5,8,9
index = network
# The sourcetype can be whatever you want
sourcetype = snmpif
```

ipsla Stanza
============

```ini
[ipsla://hostname]
destination = hostname
snmp_version = 3
v3_securityName = username
v3_authKey = password
snmpinterval = 300
operations = 2,7
index = network
sourcetype = ipsla
```

Response Handlers
=================

destination, host and /etc/hosts
--------------------------------
Currently, all response handlers set the Splunk host to the value of destination.  If you don't have DNS (bad sysadmin!) add an entry to /etc/hosts.  I'd be very happy to take a pull request that will look at a `host` config option and override `destination` with that value.

SNMP Interface Search Query
===========================

I strongly recommend you [create a search macro](http://docs.splunk.com/Documentation/Splunk/latest/Search/Usesearchmacros) `snmpif_traffic` that uses `streamstats` to calculate the bits per second from the raw `snmpif` data. My macro is:

```
stats first(*) as * by _time host ifIndex
| streamstats window=2 global=false current=true range(if*Octets) as delta*, range(_time) as secs by host, ifIndex
| where secs>0
| eval bpsIn=coalesce(deltaHCIn, deltaIn)*8/secs
| eval bpsOut=coalesce(deltaHCOut, deltaOut)*8/secs
| eval mbpsIn=bpsIn/1000000 | eval mbpsOut=bpsOut/1000000
```

Then to call it and display the results as a graph:

```
index=snmpif host=foo ifIndex=17 | `snmpif_parse`
| timechart bins=500 avg(mbpsIn) as "Mbps IN", avg(mbpsOut) as "Mbps OUT"
```

And calculate 95th percentile figures

```
index=snmpif host=foo ifIndex=17 | `snmpif_parse`
| stats perc95(mbpsIn) as "IN", perc95(mbpsOut) as "OUT"
```

Summary Collection
==================

The search term shown above is quite expensive.  I am running the query above and collecting the data into a new index.

```
[search index=network sourcetype=snmp_traffic | stats first(_time) as earliest] index=network sourcetype="snmpif"
| stats first(*) as * by _time host ifIndex
| streamstats window=2 global=false current=true range(if*Octets) as delta*, range(_time) as secs by host, ifIndex
| where secs>0
| eval bpsIn=coalesce(deltaHCIn, deltaIn)*8/secs
| eval bpsOut=coalesce(deltaHCOut, deltaOut)*8/secs
| eval mbpsIn=bpsIn/1000000
| eval mbpsOut=bpsOut/1000000
| fields _time host ifIndex bpsIn bpsOut ifAdminStatus ifDescr ifMtu ifOperStatus ifPhysAddress ifSpecific ifSpeed ifType mbpsIn mbpsOut
| collect index=network sourcetype=snmp_traffic
```

There is a trick there of using the most recent snmp_traffic event to start the next round of collections.  I run this search every 30 minutes.


About
=====

This project was originally based on [SplunkModularInputsPythonFramework](https://github.com/damiendallimore/SplunkModularInputsPythonFramework).
I have taken the SNMP modular input, refactored the python code to be more re-usable and added extra stanzas for polling interfaces and ipsla statistics.
