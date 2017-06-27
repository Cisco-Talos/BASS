from cisco.bass.util import file_sha256
from Queue import Queue, Empty
from concurrent.futures import ThreadPoolExecutor
import logging
from pkg_resources import resource_filename
from threading import Lock, Condition, current_thread, Event
from cisco.bass.thread import Thread
from cisco.bass.docker.bindiff import Client as BindiffClient
from cisco.bass.docker.bindiff import Database
import magic
import itertools
import tempfile
import subprocess
import os
import traceback
import shutil
import re
from cisco.bass.bindiffdb import BinDiff as BinDiffDb
from collectmons import defaultdict
from networkx import Graph
from networkx.drawing.nx_agraph import write_dot
from cisco.bass.algorithms import ndb_from_common_sequence, hamming_klcs
import random
from cisco.bass.avclass import ComputeVtUniqueName
from virus_total_apis import PublicApi

DUMMY_HSB_PATH = resource_filename("cisco.bass.resources", "dummy.hsb")
BINDIFF_SERVICE_URL = "http://bindiff:80"
GENERIC_CLAMAV_MALWARE_NAME = "Win.Malware.BassGeneric"
log = logging.getLogger("cisco.bass")

def start_thread(function):
    thread = Thread(target = function)
    thread.start()
    return thread


def get_num_triggering_samples(signature, samples):
    """
        Get number of samples triggering ClamAV signature _signature_.
        :param signature: A dictionary with keys 'type' for the signature type
            and 'signature' for the signature string.
        :param samples: A list of sample paths to scan.
        :returns: The number of samples triggering this signature.
    """
    handle, temp_sig = tempfile.mkstemp(suffix = "." + signature["type"])
    try:
        with os.fdopen(handle, "w") as f:
            f.write(signature["signature"])
        proc_clamscan = subprocess.Popen(["clamscan", 
                                          "-d", temp_sig,
                                          "--no-summary", "--infected"] + samples, 
                                         stdout = subprocess.PIPE,
                                         stderr = subprocess.PIPE)
        stdout, stderr = proc_clamscan.communicate()
        if not stdout:
            return 0
        else:
            return len(stdout.strip().split("\n"))
    finally:
        os.unlink(temp_sig)

def get_VT_name(hashes):
    try:
        vt = PublicApi(api_key = os.environ["VIRUSTOTAL_API_KEY"])
        generator = ComputeVtUniqueName()
        names = [generator.build_unique_name(vt.get_file_report(hash_) or "") for hash_ in hashes]
        if len(names) >= 2 and all(names[0] == name for name in names[1:]):
            name = names[0]
            if name["pup"]:
                log.error("PUA signatures are not implemented yet. Excpected name was: %s", str(name))
                pass
            else:
                return "{}.{}.{}".format(name["platform"], name["category"], name["unique_name"])
    except KeyError:
        log.warn("No VIRUSTOTAL_API_KEY specified. Falling back to generic name.")
    except Exception:
        log.exception("White trying to compute VT name. Falling back to generic name.")

    return GENERIC_CLAMAV_MALWARE_NAME

class Sample():
    def __init__(self, path, name):
        self.name = name
        self.path = path
        self.sha256 = file_sha256(path)
        self.info = {}

    def json(self):
        return {
            "name": self.name,
            "sha256": self.sha256}

class JobCanceledException(Exception):
    def __init__(self):
        super(JobCanceledException, self).__init__("The job has been canceled")

class Job():
    STATUS_CREATED = "created"
    STATUS_SUBMITTED = "submitted"
    STATUS_RUNNING = "running"
    STATUS_ERROR = "error"
    STATUS_COMPLETED = "completed"
    STATUS_CANCELED = "canceled"

    def __init__(self, job_id):
        self.samples = []
        self.status = self.STATUS_CREATED
        self.thread = None
        self.finished = Event()
        self.status_lock = Lock()
        self.id = job_id

    def add_sample(self, path, name = None):
        sample = Sample(path, name)
        self.samples.append(sample)
        return sample

    def cancel(self):
        with self.status_lock:
            if self.status == self.STATUS_RUNNING:
                self.thread.raise_exc(JobCanceledException)
            elif self.status == self.STATUS_CREATED:
                self.status = self.STATUS_CANCELED

    def json(self):
        job = {"id": self.id, "status": self.status, "samples": [s.json() for s in self.samples]}
        if self.status == self.STATUS_ERROR:
            job["error"] = {"message": str(self.exception), "stacktrace": self.exception_trace}
        elif self.status == self.STATUS_COMPLETED:
            job["result"] = self.result
        return job

class Inspector():
    DEPENDS = ()

class MagicInspector(Inspector):
    NAME = "magic"

    def inspect(self, sample):
        sample.info[self.NAME] = {"magic": magic.from_file(sample.path), "mime": magic.from_file(sample.path, mime = True)}



class SizeInspector(Inspector):
    NAME = "size"

    def inspect(self, sample):
        sample.info[self.NAME] = os.path.getsize(sample.path)

class FileTypeInspector(Inspector):
    NAME = "type"
    DEPENDS = (MagicInspector.NAME, )

    TYPE_PE = "PE"
    TYPE_UNKNOWN = "unknown"

    ASSOCIATIONS = {}

    RE_PE_EXECUTABLE = re.compile("^PE32\+? executable")
    RE_PE_NOTE = re.compile("for MS Windows, (.*)$")

    def inspect(self, sample):
        try:
            sample.info[self.NAME] = self.ASSOCIATIONS[sample.info[MagicInspector.NAME]["magic"]]
        except KeyError:
            mgc = sample.info[MagicInspector.NAME]["magic"]
            if self.RE_PE_EXECUTABLE.search(mgc):
                info = {"type": self.TYPE_PE}
                if "Intel 80386 Mono/.Net assembly" in mgc:
                    info["arch"] = "msil"
                    info["bits"] = 32
                elif "Intel 80386" in mgc:
                    info["arch"] = "x86"
                    info["bits"] = 32
                elif "ARMv7 Thumb" in mgc:
                    info["arch"] = "thumb"
                    info["bits"] = 32
                elif "ARM" in mgc:
                    info["arch"] = "arm"
                    info["bits"] = 32
                elif "x86-64" in mgc:
                    info["arch"] = "x86"
                    info["bits"] = 64
                elif "Intel Itanium" in mgc:
                    info["arch"] = "itanium"
                    info["bits"] = 64
                else:
                    log.error("Unknown architecture for PE magic string '%s'", mgc)
                    info["arch"] = "unknown"
                    info["bits"] = 0

                if "(DLL)" in mgc:
                    info["subtype"] = "dll"
                else:
                    info["subtype"] = "exe"

                if "(GUI)" in mgc:
                    info["subsystem"] = "gui"
                elif "(console)" in mgc:
                    info["subsystem"] = "console"
                elif "(native)" in mgc:
                    info["subsystem"] = "native"
                elif "(Windows CE)" in mgc:
                    info["subsystem"] = "windowsce"
                else:
                    log.info("Unknown subsystem for PE magic string '%s'", mgc)
                    info["subsystem"] = None

                info["stripped"] = "(stripped to external PDB)" in mgc
                note = self.RE_PE_NOTE.search(mgc)
                info["note"] = note.group(1) if note else None
                sample.info[self.NAME] = info
            else:
                sample.info[self.NAME] = {"type": self.TYPE_UNKNOWN}
                log.warn("Don't know file type of magic string '%s' for sample %s", sample.info[MagicInspector.NAME]["magic"], sample.sha256)

class Bass():
    def __init__(self, maxsize = 0, worker_threads = 1, unpack_threads = 1, inspect_threads = 1, idb_threads = 1, bindiff_threads = 1):
        """
            Create a Bass server.
            :param maxsize: Maximum size of the job queue. If the queue is full, jobs are rejected. 0 means unlimited.
            :param threads: Number of worker threads to use.
        """

        #TODO: Access to jobs is not threadsafe
        self.job_counter = 1
        self.jobs = {}
        self.jobs_lock = Lock()
        self.input_queue = Queue(maxsize)
        self.unpack_executor = ThreadPoolExecutor(max_workers = unpack_threads)
        self.inspect_executor = ThreadPoolExecutor(max_workers = inspect_threads)
        self.idb_executor = ThreadPoolExecutor(max_workers = idb_threads)
        self.bindiff_executor = ThreadPoolExecutor(max_workers = bindiff_threads)
        self.inspectors = [MagicInspector(), SizeInspector(), FileTypeInspector()]
        self.terminate = False
        self.threads = [start_thread(self.process_job) for _ in range(worker_threads)]
        self.bindiff = BindiffClient(urls = [BINDIFF_SERVICE_URL])

    def create_job(self):
        with self.jobs_lock:
            job = Job(self.job_counter)
            self.job_counter += 1
            self.jobs[job.id] = job
        return job

    def submit_job(self, job_id):
        """
            :excepts: KeyError if job is not found, and queue.Full if job queue is full.
        """
        with self.jobs_lock:
            job = self.jobs[job_id]
            with job.status_lock:
                self.input_queue.put(job, False)
                job.status = Job.STATUS_SUBMITTED

    def list_jobs(self):
        with self.jobs_lock:
            return list(self.jobs.values())

    def get_job(self, job_id):
        with self.jobs_lock:
            return self.jobs[job_id]

    def delete_job(self, job_id):
        with self.jobs_lock:
            job = self.jobs[job_id]
            job.cancel()
            del self.jobs[job_id]
            

    def terminate(self):
        self.terminate = True
        for job in self.jobs:
            job.cancel()
        self.unpack_executor.shutdown()
        self.inspect_executor.shutdown()

    def process_job(self):
        while not self.terminate:
            try:
                job = self.input_queue.get(1)
            except Empty:
                continue

            temporary_paths = []
            try:
                with job.status_lock:
                    if job.status == Job.STATUS_CANCELED:
                        continue
                    job.thread = current_thread()
                    job.status = Job.STATUS_RUNNING

                def unpack(sample):
                    unpack_dir = tempfile.mkdtemp()
                    subprocess.check_call(["clamscan", "-d", DUMMY_HSB_PATH, "--leave-temps", "--tempdir", unpack_dir, "--no-summary", "--quiet", sample.path])
                    sample.fragments =  [Sample(os.path.join(dp, f), f) for dp, _, filenames in os.walk(unpack_dir) for f in filenames]
                    if sample.fragments:
                        temporary_paths.append(unpack_dir)
                    else:
                        os.rmdir(unpack_dir)

                list(self.unpack_executor.map(unpack, job.samples))

                def inspect(sample):
                    for inspector in self.inspectors:
                        inspector.inspect(sample)

                list(self.inspect_executor.map(inspect, itertools.chain(job.samples, (fragment for sample in job.samples for fragment in sample.fragments))))

                # For packed PE samples, replace them with their unpacked version
                for i in range(len(job.samples)):
                    sample = job.samples[i]
                    if sample.info[FileTypeInspector.NAME]["type"] == FileTypeInspector.TYPE_PE and "packed" in sample.info[FileTypeInspector.NAME]:
                        pe_fragments = [x for x in sample.fragments if x.info[FileTypeInspector.NAME]["type"] == FileTypeInspector.TYPE_PE]
                        if len(pe_fragments) == 1:
                            job.samples[i] = pe_fragments[0]
                        elif len(pe_fragments) == 0:
                            log.info("Original sample %s is packed, but ClamAV couldn't extract the packed sample. Continuing with the original sample.", sample.sha256)
                        else:
                            log.warn("Original sample %s is packed, and more than one PE files have been extracted from it. Don't know how to continue, will use original sample", sample.sha256)

                # If all samples are PE, send them to Bindiff/LCS
                if all(x.info[FileTypeInspector.NAME]["type"] == FileTypeInspector.TYPE_PE for x in job.samples):
                    job.result = self._build_bindiff_lcs_signature(job)
                else:
                    log.error("Cannot handle a case where not all samples are PE files yet")
                    raise NotImplementedError("Cannot handle a case where not all samples are PE files yet")
                with job.status_lock:
                    job.status = Job.STATUS_COMPLETED
            except JobCanceledException:
                with job.status_lock:
                    job.status = Job.STATUS_CANCELED
            except Exception as ex:
                trace = traceback.format_exc()
                log.exception("Exception while handling job")
                with job.status_lock:
                    job.exception = ex
                    job.exception_trace =trace
                    job.status = Job.STATUS_ERROR
            finally:
                for path in (temporary_paths + [s.path for s in job.samples]):
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.unlink(path)
                log.info("Job %d has finished: %s", job.id, job.status)
                if job.status == Job.STATUS_ERROR:
                    print(job.exception)

                job.finished.set()

    def _build_bindiff_lcs_signature(self, job):
        log.info("Building a Bindiff/LCS signature for job %d", job.id)
#        if (len(job.samples) != 2):
#            return {"message": "Can only handle two samples at the moment"}
        temporary_paths = []
        try:
            ida_pickle_dbs = list(self.idb_executor.map(lambda sample: self.bindiff.bindiff_pickle_export(sample.path, sample.info[FileTypeInspector.NAME]["bits"] == 64), job.samples))
            binexport_dbs = [binexport_db for binexport_db, _ in ida_pickle_dbs]
            pickle_dbs = [pickle_db for _, pickle_db in ida_pickle_dbs]
            
            temporary_paths += binexport_dbs
            temporary_paths += pickle_dbs

            # TODO: Find a clever way of generating few bindiff comparisons
            binexport_pairs = list(itertools.combinations(binexport_dbs, 2))
            pickle_pairs = list(itertools.combinations(pickle_dbs, 2))
            log.debug("Comparing %d pairs of binaries with each other", len(pickle_pairs))
            bindiff_dbs = list(self.bindiff_executor.map(lambda x: self.bindiff.bindiff_compare(*x), binexport_pairs))
            temporary_paths += bindiff_dbs

            log.debug("Building graph of similar functions")
            graph = Graph()

            for bindiff_db_path, (sample1_pickle_db_path, sample2_pickle_db_path) in zip(bindiff_dbs, pickle_pairs):
                sample1_db = Database.load(sample1_pickle_db_path)
                sample2_db = Database.load(sample2_pickle_db_path)
                bindiff_db = BinDiffDb(bindiff_db_path)

                assert(bindiff_db.get_binary(1).get_exefilename() == sample1_db.filename)
                assert(bindiff_db.get_binary(2).get_exefilename() == sample2_db.filename)
    
                for similar_func in bindiff_db.get_similar_functions(min_similarity = 0.6,
                                                                     min_confidence = 0.5,
                                                                     min_instructions = 50,
                                                                     min_bbs = 3,
                                                                     min_edges = 4,
                                                                     limit = 10):
                    # TODO: The weight might need to be tuned
                    weight = similar_func["similarity"] * similar_func["confidence"]
                    graph.add_edge((sample1_db, int(similar_func["address1"])),
                                   (sample2_db, int(similar_func["address2"])),
                                   weight = weight)

            # What we want here is to find subgraphs in the graph which have a high accumulated average weight
            log.debug("Finding connected subgraphs in the graph")
            subgraphs = []
            processed_nodes = set()

            for node in graph.nodes():
                if node in processed_nodes:
                    continue

                binaries = set()
                nodes_to_explore = set((node, ))
                subgraph = Graph()
                while nodes_to_explore:
                    cur_node = nodes_to_explore.pop()

                    for edge in graph.edges(cur_node):
                        assert(edge[0] == cur_node)

                        # We don't want the same binary twice in our subgraph
                        if edge[1][0] in binaries:
                            continue

                        # We don't want circles in our subgraph
                        if edge[1] in subgraph.nodes():
                            continue

                        # This should happen only in obscure cases where we
                        # stopped at a node because of the same binary
                        # occurring twice (with different functions)
                        if edge[1] in processed_nodes:
                            continue

                        subgraph.add_edge(*edge)
                        nodes_to_explore.add(edge[1])

                    processed_nodes.add(cur_node)

                subgraphs.append(subgraph)

            if not subgraphs:
                log.info("No connected subgraphs in the function similarity graph found")
                return {"signatures": [], "message": "Cannot find common functions within the binaries"}

            
            log.debug("Determining maximal subgraph among %d subgraphs", len(subgraphs))
            max_score =  float("-infinity")
            max_subgraph = None
            for subgraph in subgraphs:
                # Just use the sum of similarities as a measure. We want bigger
                # subgraphs to have a higher score, so this is a good way to
                # insure it.
                score = sum(graph.get_edge_data(*x)["weight"] for x in subgraph.edges()) #/ len(subgraph.edges())
                if score > max_score:
                    max_score = score
                    max_subgraph = subgraph
            
            if max_subgraph is None:
                log.info("No maximal subgraph found")
                return {"signatures": [], "message": "No maximal subgraph found"}

            log.debug("Found maximal subgraph with %d nodes, score %f", len(max_subgraph.nodes()), int(max_score * 100) / 100.0)

            # Right now, we'll just generate a signature for the subgraph with
            # the biggest score. In the future, we could try to find a set of
            # subgraphs with cover the cluster best.

            log.debug("Getting binary code for maximal subgraph")
            # Get the code for each function
            functions_code = []
            for sample_db, function_ep in max_subgraph.nodes():
                function = sample_db.get_function(function_ep)
                log.debug("Function %s:%d has %d chunks", sample_db.sha256, function_ep, len(list(function.chunks)))
                #TODO: This is wrong. You cannot simply append this, in case there are gaps between the chunks,
                # a '*' operator needs to be inserted in the final sig
                functions_code.append("".join(chunk.bytes for chunk in function.chunks))
            log.debug("Longest code sequence is %s bytes", max(len(x) for x in functions_code))

            log.debug("Finding common subsequence in binary code")
            common_seq = hamming_klcs(functions_code)
            #TODO: Shorten sequence to maximum acceptable length of 980 bytes
            #(ClamAV ndb signature length limit)
            while len(common_seq) > 950:
                kill_character = random.randint(0, len(common_seq) - 1)
                common_seq = common_seq[:kill_character] + common_seq[kill_character + 1:]
            ndb_signature = ndb_from_common_sequence(functions_code, common_seq)

            log.debug("Found ndb signature: '%s'", ndb_signature)

            if ndb_signature:
                # TODO: Make nice name
                name = get_VT_name([sample.sha256 for sample in job.samples])
                signature = {"type": "ndb", "signature":  "{}:1:*:{}".format(name, ndb_signature)}
                num_triggering_samples = get_num_triggering_samples(signature, [sample.path for sample in job.samples])
                log.debug("Signature triggered by %d samples (%.02f %%)",
                    num_triggering_samples, 
                    int(10000.0 * num_triggering_samples / len(job.samples)) / 100.0)
                return {"signatures": 
                            [
                                {"signature": signature,
                                 "metrics":
                                    {"coverage": 1.0 * num_triggering_samples / len(job.samples),
                                     "num_triggering_samples": num_triggering_samples}
                                }
                            ],
                         "message": "Found signature"
                        }
            else:
                return {"signatures": [], "message": "Did not find a common sequence between code"}
        finally:
            for path in temporary_paths:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
