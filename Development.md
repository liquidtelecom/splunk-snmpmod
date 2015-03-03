cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config snmp snmp://HRE | splunk cmd python $env:SPLUNK_HOME/etc/apps/snmp_ta/bin/snmp.py

cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config --debug snmp snmp://HRE 2>&1 > out.tx

./update.ps1 ; splunk cmd splunkd print-modinput-config snmp snmp://HRE





# SNMP IFACE


./update.ps1 ; splunk cmd splunkd print-modinput-config snmpif snmpif://tst

cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config --debug snmpif snmpif://tst 2>&1 > out.txt


splunk cmd python $env:SPLUNK_HOME/etc/apps/snmp_ta/bin/snmpif.py

cls ; ./update.ps1 ; splunk cmd splunkd print-modinput-config snmpif snmpif://tst | splunk cmd python $env:SPLUNK_HOME/etc/apps/snmp_ta/bin/snmpif.py --validate-arguments



Check the interfaces
snmpwalk -v 3 -u ecouser -A deepf1neleg 46.17.232.130  IF-MIB::ifDescr

snmpwalk -v 3 -u ecouser -A deepf1neleg 46.17.232.131 IF-MIB::ifDescr



splunk cmd splunkd print-modinput-config snmpif snmpif://LRW-PE2-KGL | splunk cmd python $SPLUNK_HOME/etc/apps/snmp_ta/bin/snmpif.py