# add your custom response handler class to this module
import sys
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
                except:  # catch *all* exceptions
                    e = sys.exc_info()[1]
                    splunkevent += '%s =  ' % e
                try:
                    decoded_val = mibvar.cloneFromMibValue(mib_view, mod_name, sym_name, val)
                    splunkevent += '%s ' % (decoded_val.prettyPrint())
                except:  # catch *all* exceptions
                    e = sys.exc_info()[1]
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