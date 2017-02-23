import logging
import argparse
import os
import sys
import time
from cisco.bass.server import Bass, Job
import signal

def main(args, env):
    if len(args.samples) < 2:
        sys.stderr.write("Come on, give me at least two samples :(\n")
        return 1

    bass = Bass()
    job = Job()
    def received_sigterm(signal, frame):
        sys.stderr.write("Received SIGINT\n")
        bass.terminate()

    signal.signal(signal.SIGINT, received_sigterm)
    for path in args.samples:
        job.add_sample(path)
    bass.submit_job(job)
    while not job.status in (Job.STATUS_ERROR, Job.STATUS_FINISHED, Job.STATUS_CANCELED):
        time.sleep(1)

def parse_args():
    parser = argparse.ArgumentParser(description = "Bass")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity")
    parser.add_argument("samples", metavar = "sample", nargs = "+", help = "Sample path") 

    args = parser.parse_args()

    try:
        loglevel = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO
        }[args.verbose]
    except KeyError:
        loglevel = logging.DEBUG

    logging.basicConfig(level = loglevel)
    logging.getLogger().setLevel(loglevel)

    return args

if __name__ == "__main__":
    ret = main(parse_args(), os.environ)
    sys.exit(0 if ret is None else ret)
