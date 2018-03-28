import requests
import logging
import argparse
import sys
import os

log = logging.getLogger("cisco.bass.client")

def main(args, env):
    response = requests.post("{:s}/whitelist".format(args.url), files = {"file": open(args.sample, "rb")})
    if response.status_code != 200:
        print("Server returned error {:d}: {:s}".format(response.status_code, response.content))

def parse_args():
    parser = argparse.ArgumentParser(description = "Add samples to BASS whitelist")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity")
    parser.add_argument("--url", type = str, default = "http://localhost:5000", help = "URL of BASS server")
    parser.add_argument("sample", help = "Whitelist sample")

    args = parser.parse_args()

    try:
        loglevel = {
            0: logging.ERROR,
            1: logging.WARN,
            2: logging.INFO}[args.verbose]
    except KeyError:
        loglevel = logging.DEBUG
    logging.basicConfig(level = loglevel)
    logging.getLogger().setLevel(loglevel)

    return args

if __name__ == "__main__":
    ret = main(parse_args(), os.environ)
    if ret is not None:
        sys.exit(ret)
