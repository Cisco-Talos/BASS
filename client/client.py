import requests
import time
import logging
import argparse
import sys
import os

log = logging.getLogger("cisco.bass.client")

class Job():
    def __init__(self, url, data):
        self.data = data
        self.url = url

    def wait(self):
        while self.status != "error" and self.status != "completed":
            time.sleep(1)
            reply = requests.get("%s/job/%d" % (self.url, self.data["id"]))
            if reply.status_code != 200:
                try:
                    message = reply.json()["message"]
                except ValueError:
                    message = reply.content
                raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))
            self.data = reply.json()["job"]
        return self.status
        

    @property
    def id(self):
        return self.data["id"]

    @property
    def status(self):
        return self.data["status"]

    @property
    def result(self):
        return self.data["result"]

    @property
    def exception(self):
        return self.data["error"]["message"]

    @property
    def exception_trace(self):
        return self.data["error"]["stacktrace"]

    def add_sample(self, paths):
        if isinstance(paths, str):
            paths = [paths]
        reply = requests.post("%s/job/%d/add_sample" % (self.url, self.id), files = [(path, open(path, "rb")) for path in paths])
        if reply.status_code != 200:
            try:
                message = reply.json()["message"]
            except ValueError:
                message = reply.content
            raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))

    def submit(self):
        reply = requests.post("%s/job/%d/submit" % (self.url, self.id))
        if reply.status_code != 200:
            try:
                message = reply.json()["message"]
            except ValueError:
                message = reply.content
            raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))

    def delete(self):
        reply = requests.delete("%s/job/%d" % (self.url, self.id))
        if reply.status_code != 200:
            try:
                message = reply.json()["message"]
            except ValueError:
                message = reply.content
            raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))



class Bass():
    def __init__(self, url):
        self.url = url

    def create_job(self):
        reply = requests.post("%s/job" % self.url)
        if reply.status_code == 200:
            return Job(self.url, reply.json()["job"])
        else:
            try:
                message = reply.json()["message"]
            except ValueError:
                message = reply.content
            raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))

    def list_jobs(self):
        reply = requests.get("%s/job" % self.url)
        if reply.status_code == 200:
            return [Job(self.url, job) for job in reply.json()["jobs"]]
        else:
            try:
                message = reply.json()["message"]
            except ValueError:
                message = reply.content
            raise RuntimeError("Server returned error code %d: %s" % (reply.status_code, message))

################# Command line interface ###########################


def main(args, env):
    bass = Bass(args.url)
    job = bass.create_job()
    for sample in args.samples:
        job.add_sample(sample)
    job.submit()
    status = job.wait()
    if status == "completed":
        log.info("Job completed, generated signature is %s", job.result)

        if not job.result["signatures"]:
            if args.output:
                sys.stderr.write("No signature found\n")
            else:
                log.warn("No signature found")
        else:
            signature = job.result["signatures"][0]
            if len(job.result["signatures"]) > 1:
                log.warn("Got more than one signature, only using the first one")
            log.info("Singature '%s' type %s is triggering on %d samples (%05.2f%%)",
                    signature["signature"]["signature"],
                    signature["signature"]["type"],
                    signature["metrics"]["num_triggering_samples"],
                    signature["metrics"]["coverage"] * 100.0)
            if args.output:
                if os.path.splitext(args.output)[1].lower() != signature["signature"]["type"]:
                    log.warn("Signature output file extension %s does not " + \
                             "correspond to signature type %s",
                             os.path.splitext(args.output)[1], signature["signature"]["type"])
                else:
                    with open(args.output, "w") as f:
                        f.write(signature["signature"]["signature"])
            else:
                print(signature["signature"]["signature"])
        return 0
    elif status == "error":
        log.error("Exception '%s' while running job. Stacktrace:\n%s", job.exception, job.exception_trace)
        return 1

def parse_args():
    parser = argparse.ArgumentParser(description = "Find common ngrams in binary files")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity")
    parser.add_argument("--output", type = str, default = None, help = "Output to file instead of stdout")
    parser.add_argument("--url", type = str, default = "http://localhost:5000", help = "URL of BASS server")
    parser.add_argument("samples", metavar = "sample", nargs = "+", help = "Cluster samples")

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
