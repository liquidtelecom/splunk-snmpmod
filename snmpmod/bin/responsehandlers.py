"""
Response Handlers for the SNMP Mod app
"""
import json
import string
from datetime import datetime

from pysnmp.entity.rfc3413 import mibvar
from pysnmp.proto.rfc1905 import NoSuchInstance


def splunk_escape(input_string):
    s = string.replace(input_string, "'", "")
    if any(c in string.whitespace for c in s):
        return "\"%s\"" % s
    else:
        return s


class InterfaceResponseHandler:
    def __init__(self, **args):
        pass

    def __call__(self, response_object, destination):
        splunkevent = "%s " % (datetime.isoformat(datetime.utcnow()))
        for name, val in response_object:
            symbol = name.getMibSymbol()[1]
            if not isinstance(val, NoSuchInstance):
                splunkevent += '%s=%s ' % (symbol, splunk_escape(val.prettyPrint()))
        print_xml_single_instance_mode(destination, splunkevent)


class IpslaResponseHandler:
    def __init__(self, **args):
        pass

    # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.4.1.9.9.42.1.5.2.1.46
    symbols = {
        '1.3.6.1.4.1.9.9.42.1.5.2.1.1': 'latestJitterNumOfRTT',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.2': 'latestJitterRTTSum',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.4': 'latestJitterRTTMin',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.5': 'latestJitterRTTMax',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.26': 'latestJitterPacketLossSD',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.27': 'latestJitterPacketLossDS',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.28': 'latestJitterPacketOutOfSequence',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.29': 'latestJitterPacketMIA',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.30': 'latestJitterPacketLateArrival',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.31': 'latestJitterSense',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.46': 'latestJitterAvgJitter',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.53': 'latestJitterRTTSumHigh',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.1': 'latestRttCompletionTime',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.4': 'latestRttSenseDescription',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.5': 'latestRttTime',
    }

    @staticmethod
    def get_mib_symbol(name):

        if name in IpslaResponseHandler.symbols:
            return IpslaResponseHandler.symbols[name]
        else:
            return 'unknown'

    def __call__(self, response_object, destination, operation):
        splunkevent = "%s operation=%s " % (datetime.isoformat(datetime.utcnow()), operation)
        for name, val in response_object:
            # getOid() gives you an ObjectIdentifier from pyasn.  I am stripping the last item off the list and turning
            # it into a string for the dictionary.
            symbol = self.get_mib_symbol(str(name.getOid()[0:-1]))
            if not isinstance(val, NoSuchInstance):
                splunkevent += '%s=%s ' % (symbol, splunk_escape(val.prettyPrint()))
        print_xml_single_instance_mode(destination, splunkevent)


# the default handler , does nothing , just passes the raw output directly to STDOUT
class DefaultResponseHandler:
    def __init__(self, **args):
        pass

    def __call__(self, response_object, destination, table=False, from_trap=False, trap_metadata=None,
                 split_bulk_output=False, mib_view=None):
        splunkevent = ""

        # handle traps
        if from_trap:
            for oid, val in response_object:
                sym_name = None
                mod_name = None
                try:
                    (sym_name, mod_name), indices = mibvar.oidToMibName(mib_view, oid)
                    splunkevent += '%s::%s.%s =  ' % (mod_name, sym_name, '.'.join([v.prettyPrint() for v in indices]))
                except Exception as e:  # catch *all* exceptions
                    splunkevent += '%s =  ' % e
                try:
                    decoded_val = mibvar.cloneFromMibValue(mib_view, mod_name, sym_name, val)
                    splunkevent += '%s ' % (decoded_val.prettyPrint())
                except Exception as e:  # catch *all* exceptions
                    splunkevent += '%s ' % e
            splunkevent = trap_metadata + splunkevent
            print_xml_single_instance_mode(destination, splunkevent)

        # handle tables
        elif table:
            for varBindTableRow in response_object:
                for name, val in varBindTableRow:
                    output_element = '%s = "%s" ' % (name.prettyPrint(), val.prettyPrint())
                    if split_bulk_output:
                        print_xml_single_instance_mode(destination, output_element)
                    else:
                        splunkevent += output_element
            print_xml_single_instance_mode(destination, splunkevent)
            # handle scalars
        else:
            for name, val in response_object:
                splunkevent += '%s = "%s" ' % (name.prettyPrint(), val.prettyPrint())
            print_xml_single_instance_mode(destination, splunkevent)


class JSONFormatterResponseHandler:
    def __init__(self, **args):
        pass

    def __call__(self, response_object, destination, table=False, from_trap=False, trap_metadata=None,
                 split_bulk_output=False, mib_view=None):
        # handle tables
        if table:
            values = []
            for varBindTableRow in response_object:
                row = {}
                for name, val in varBindTableRow:
                    row[name.prettyPrint()] = val.prettyPrint()
                values.append(row)
            print_xml_single_instance_mode(destination, json.dumps(values))
            # handle scalars
        else:
            values = {}
            for name, val in response_object:
                values[name.prettyPrint()] = val.prettyPrint()
            print_xml_single_instance_mode(destination, json.dumps(values))


            # prints XML stream


def print_xml_single_instance_mode(server, event):
    print "<stream><event><data>%s</data><host>%s</host></event></stream>" % (
        encode_xml_text(event), server)


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


def encode_xml_text(text):
    text = text.replace("&", "&amp;")
    text = text.replace("\"", "&quot;")
    text = text.replace("'", "&apos;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    text = text.replace("\n", "")
    return text
