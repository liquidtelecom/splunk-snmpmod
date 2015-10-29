"""
SNMP IPSLA Statistics Modular Input
"""

import time
from datetime import datetime

import snmputils
import responsehandlers
from pysnmp.proto.rfc1905 import NoSuchInstance
from SnmpStanza import *

runner = Ipsla()


class IpslaResponseHandler:
    def __init__(self, **args):
        pass

    # http://tools.cisco.com/Support/SNMP/do/BrowseOID.do?objectInput=1.3.6.1.4.1.9.9.42.1.5.2.1.1
    # http://www.oidview.com/mibs/9/CISCO-RTTMON-MIB.html
    symbols = {
        '1.3.6.1.4.1.9.9.42.1.5.2.1.1': 'latestJitterNumOfRTT',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.2': 'latestJitterRTTSum',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.3': 'latestJitterRTTSum2',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.4': 'latestJitterRTTMin',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.5': 'latestJitterRTTMax',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.26': 'latestJitterPacketLossSD',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.27': 'latestJitterPacketLossDS',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.28': 'latestJitterPacketOutOfSequence',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.29': 'latestJitterPacketMIA',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.30': 'latestJitterPacketLateArrival',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.31': 'latestJitterSense',
        '1.3.6.1.4.1.9.9.42.1.5.2.1.46': 'latestJitterAvgJitter',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.1': 'latestRttCompletionTime',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.2': 'latestRttOperationResponse',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.4': 'latestRttSenseDescription',
        '1.3.6.1.4.1.9.9.42.1.2.10.1.5': 'latestRttTime',
        '1.3.6.1.4.1.9.9.42.1.3.5.1.34': 'jitterStatsPacketLossSD',
        '1.3.6.1.4.1.9.9.42.1.3.5.1.35': 'jitterStatsPacketLossDS',
        '1.3.6.1.4.1.9.9.42.1.3.5.1.37': 'jitterStatsPacketLossMIA',
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
                splunkevent += '%s=%s ' % (symbol, responsehandlers.splunk_escape(val.prettyPrint()))
        responsehandlers.print_xml_single_instance_mode(destination, splunkevent)


def do_run():
    runner.read_config()

    try:
        # update all the root StreamHandlers with a new formatter that includes the config information
        for h in logging.root.handlers:
            if isinstance(h, logging.StreamHandler):
                h.setFormatter(logging.Formatter('%(levelname)s ipsla="{0}" %(message)s'.format(runner.name())))

    except Exception as e:  # catch *all* exceptions
        logging.exception("Couldn't update logging templates: %s" % e)

    # MIBs to load
    mib_names_args = ['IF-MIB']

    global mib_view
    cmd_gen, mib_view = snmputils.get_cmd_gen(mib_names_args)

    try:
        while True:
            try:
                for operation in runner.operations():
                    oid_args = [str(b + '.' + operation) for b in IpslaResponseHandler.symbols]
                    error_indication, error_status, error_index, var_binds = cmd_gen.getCmd(
                        runner.security_object(), runner.transport(), *oid_args, lookupNames=True, lookupValues=True)
                    if error_indication:
                        logging.error(error_indication)
                    elif error_status:
                        logging.error(error_status)
                    else:
                        handle_output(var_binds, runner.destination(), operation)

            except Exception as ex:  # catch *all* exceptions
                logging.exception("Exception with getCmd to %s:%s %s" % (runner.destination(), runner.port, ex))
                time.sleep(float(runner.snmpinterval()))
                continue

            time.sleep(float(runner.snmpinterval()))

    except Exception as ex:
        logging.exception("Exception in run: %s" % ex)
        sys.exit(1)


def handle_output(response_object, destination, operation):
    try:
        handler = IpslaResponseHandler()
        handler(response_object, destination, operation)
        sys.stdout.flush()
    except Exception as ex:
        logging.exception("Looks like an error handle the response output %s" % ex)


def do_validate():
    try:
        runner.read_config()
        if not runner.is_valid():
            logging.error("Validation failed")
            sys.exit(2)
    except Exception as ex:
        logging.exception("Exception validating %s" % ex)
        sys.exit(1)


def do_scheme():
    print runner.scheme()


def usage():
    print "usage: %s [--scheme|--validate-arguments]"
    logging.error("Incorrect Program Usage")
    sys.exit(2)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "--scheme":
            do_scheme()
        elif sys.argv[1] == "--validate-arguments":
            do_validate()
        else:
            usage()
    else:
        do_run()
    sys.exit(0)
