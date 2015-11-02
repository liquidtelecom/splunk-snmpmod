These are development notes for working with SNMP and Splunk.  I dev on windows so they're all Powershell based

cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config snmp snmp://HRE | splunk cmd python $env:SPLUNK_HOME/etc/apps/snmpmod/bin/snmp.py

cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config --debug snmp snmp://HRE 2>&1 > out.tx

./update.ps1 ; splunk cmd splunkd print-modinput-config snmp snmp://HRE



SNMP IFACE
==========

```shell
# Print out the config
splunk cmd splunkd print-modinput-config snmpif snmpif://tst | Out-File snmpif.xml

# Run it using the script in the dev directory
cat snmpif.xml | splunk cmd python snmpmod/bin/snmpif.py



./updateDevSplunk.ps1 ; splunk cmd splunkd print-modinput-config snmpif snmpif://tst
cls ; ./updateDevSplunk.ps1 ; splunk cmd splunkd print-modinput-config --debug snmpif snmpif://tst 2>&1 > out.txt
splunk cmd python $env:SPLUNK_HOME/etc/apps/snmpmod/bin/snmpif.py
cls ; ./updateDevSplunk.ps1 ; splunk cmd splunkd print-modinput-config snmpif snmpif://tst | splunk cmd python $env:SPLUNK_HOME/etc/apps/snmpmod/bin/snmpif.py --validate-arguments


# Check the interfaces
snmpwalk -v 3 -u ecouser -A deepf1neleg 46.17.232.130  IF-MIB::ifDescr

snmpwalk -v 3 -u ecouser -A deepf1neleg 46.17.232.131 IF-MIB::ifDescr

splunk cmd splunkd print-modinput-config snmpif snmpif://LRW-PE2-KGL | splunk cmd python $SPLUNK_HOME/etc/apps/snmpmod/bin/snmpif.py
```


IPSLA Statistics
================

```shell
./updateDevSplunk.ps1 ; splunk cmd splunkd print-modinput-config ipsla ipsla://tst | splunk cmd python $env:SPLUNK_HOME/etc/apps/snmpmod/bin/ipsla.py --validate-arguments
```


Splunk
======
Update from command line

```shell
splunk install app target/snmpmod.spl -update 1 -auth admin:changeme
```
