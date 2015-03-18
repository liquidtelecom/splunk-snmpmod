"""
SNMP IPSLA Statistics Modular Input
"""

import time
import os
import sys

from responsehandlers import IpslaResponseHandler


SPLUNK_HOME = os.environ.get("SPLUNK_HOME")

# dynamically load in any eggs in /etc/apps/snmp_ta/bin
egg_dir = os.path.join(SPLUNK_HOME, "etc", "apps", "snmpmod", "bin")
for filename in os.listdir(egg_dir):
    if filename.endswith(".egg"):
        sys.path.append(egg_dir + filename)

# directory of the custom MIB eggs
mib_egg_dir = os.path.join(egg_dir, "mibs")
sys.path.append(mib_egg_dir)
for filename in os.listdir(mib_egg_dir):
    if filename.endswith(".egg"):
        sys.path.append(os.path.join(mib_egg_dir, filename))

from pysnmp.smi import builder
from pysnmp.smi import view
from SnmpStanza import *

runner = Ipsla()


def get_cmd_gen(mib_names_args):
    global mib_view
    # load in custom MIBS
    cmd_gen = cmdgen.CommandGenerator()
    mib_builder = cmd_gen.snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder
    mib_sources = (builder.DirMibSource(mib_egg_dir),)
    for mibfile in os.listdir(mib_egg_dir):
        if mibfile.endswith(".egg"):
            mib_sources = mib_sources + (builder.ZipMibSource(mibfile),)
    mib_sources = mib_builder.getMibSources() + mib_sources
    mib_builder.setMibSources(*mib_sources)
    if mib_names_args:
        mib_builder.loadModules(*mib_names_args)
    mib_view = view.MibViewController(mib_builder)
    return cmd_gen, mib_view


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
    cmd_gen, mib_view = get_cmd_gen(mib_names_args)

    try:
        while True:
            try:
                for entry in runner.entries():
                    oid_args = [str(b + '.' + entry) for b in IpslaResponseHandler.symbols]
                    error_indication, error_status, error_index, var_binds = cmd_gen.getCmd(
                        runner.security_object(), runner.transport(), *oid_args, lookupNames=True, lookupValues=True)
                    if error_indication:
                        logging.error(error_indication)
                    elif error_status:
                        logging.error(error_status)
                    else:
                        handle_output(var_binds, runner.destination(), entry)

            except Exception as ex:  # catch *all* exceptions
                logging.exception("Exception with getCmd to %s:%s %s" % (runner.destination(), runner.port, ex))
                time.sleep(float(runner.snmpinterval()))
                continue

            time.sleep(float(runner.snmpinterval()))

    except Exception as ex:
        logging.exception("Exception in run: %s" % ex)
        sys.exit(1)


def handle_output(response_object, destination, entry):
    try:
        from responsehandlers import IpslaResponseHandler

        handler = IpslaResponseHandler()
        handler(response_object, destination, entry)
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
