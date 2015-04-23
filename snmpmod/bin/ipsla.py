"""
SNMP IPSLA Statistics Modular Input
"""

import time

import snmputils
import responsehandlers
from SnmpStanza import *

runner = Ipsla()


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
                    oid_args = [str(b + '.' + operation) for b in responsehandlers.IpslaResponseHandler.symbols]
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
        from responsehandlers import IpslaResponseHandler

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
