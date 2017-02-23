# System imports
import itertools
import logging
import json
from collections import defaultdict
import os
import pickle
import tempfile
import subprocess
import shutil

# Third party imports
import requests

SHARED_FOLDER = os.environ.get("BINDIFF_SHARED_FOLDER", "/bindiff")

log = logging.getLogger("cisco.bass")


class BasicBlock():
    def __init__(self, function, data):
        self.function = function
        self.data = data

    @property
    def bytes(self):
        return self.function.db.get_bytes(self.start, self.end)

    @property
    def start(self):
        return self.data["start"]

    @property
    def end(self):
        return self.data["end"]

    @property
    def id(self):
        return self.data["id"]

    @property
    def name(self):
        return "loc_%X" % self.data["start"]

    @property
    def thumb(self):
        if self.function.db.architecture_name == "arm":
            return self.function.db.get_head(self.start)["thumb"]
        else:
            return None

    @property
    def code_heads(self):
        return (self.function.db.get_head(hd) for hd in self.data["code_heads"])

    @property
    def successors(self):
        return (self.function.bb[bb] for bb in self.data["successors"])


class Chunk():
    def __init__(self, function, data):
        self.function = function
        self.data = data

    @property
    def start(self):
        return self.data["start"]

    @property
    def end(self):
        return self.data["end"]

    @property
    def bytes(self):
        return self.function.db.get_bytes(self.start, self.end)

class Function():
    def __init__(self, db, data):
        self.db = db
        self.data = data
        self.bb = dict((x["id"], BasicBlock(self, x)) for x in self.data["basic_blocks"])

    @property
    def entry_point(self):
        return self.data["entry_point"]

    @property
    def name(self):
        return self.data["name"]

    @property
    def chunks(self):
        return (Chunk(self, chunk) for chunk in self.data["chunks"])

    @property
    def calls(self):
        return self.db.get_callees(self.entry_point)

    @property
    def basic_blocks(self):
        return self.bb.values()

    @property
    def apis(self):
        return [x["name"] for x in self.data["api_calls"]]

class Segment():
    def __init__(self, db, data):
        self.db = db
        self.data = data

    @property
    def start(self):
        return self.data["virtual_address"]

    @property
    def end(self):
        return self.data["virtual_address"] + self.data["virtual_size"]

    @property
    def bytes(self):
        return self.data["data"]

    @property
    def file_offset(self):
        return self.data["file_offset"]

    def get_head(self, address):
        return Head(self, self.data["code_heads"][address], address)

    def get_bytes(self, start, end):
        if self.bytes is None:
            return None
        return self.bytes[start - self.start : end - self.start]

class Head():
    def __init__(self, segment, data, address):
        self.segment = segment
        self.data = data
        self.address = address

    @property
    def is_code_head(self):
        return self.data["type"] == "code"

    @property
    def is_data_head(self):
        return self.data["type"] == "data"

    @property
    def data_refs(self):
        return self.data["data_refs"]

    @property
    def code_refs(self):
        return self.data["code_refs"]

    @property
    def flow(self):
        return self.data["flow_refs"]

    @property
    def size(self):
        return self.data["size"]

    @property
    def bytes(self):
        return self.segment.get_bytes(self.address, self.address + self.size)

    @property
    def mnemonic(self):
        return self.data["mnem"]

    @property
    def disassembly(self):
        return self.data["disasm"]

class Database():
    def __init__(self, data):
        self.data = data
        self.callees = defaultdict(set)
        self.ep_to_function = dict((x["entry_point"], x) for x in self.data["functions"])
        for func in self.data["functions"]:
            for call in func["called_from"]:
                self.callees[call].add(func["entry_point"])

    def get_bytes(self, start, end):
        for seg in self.segments:
            if seg.start <= start and end <= seg.end:
                return seg.get_bytes(start, end)
        return None

    @property
    def architecture_name(self):
        return "mips" if self.data["architecture"]["name"].lower().startswith("mips") else \
            self.data["architecture"]["name"].lower()

    @property
    def architecture_bits(self):
        return self.data["architecture"]["bits"]

    @property
    def architecture_endianness(self):
        return self.data["architecture"]["endian"]

    @property
    def functions(self):
        return (Function(self, x) for x in self.data["functions"])

    @property
    def segments(self):
        return (Segment(self, x) for x in self.data["segments"])

    @property
    def filename(self):
        return self.data["filename"]

    @property
    def md5(self):
        return self.data["md5"].lower()

    @property
    def sha1(self):
        return self.data["sha1"].lower()

    @property
    def sha256(self):
        return self.data["sha256"].lower()

    @property
    def sha512(self):
        return self.data["sha512"].lower()

    def get_callees(self, func):
        return list(self.callees[func]) if func in self.callees else []

    def get_head(self, address):
        for seg in self.segments:
            if seg.start <= address and address < seg.end:
                return seg.get_head(address)
        raise RuntimeError("Head 0x%x not found in database" % address)

    def get_function(self, address):
        try:
            return Function(self, self.ep_to_function[address])
        except KeyError:
            raise RuntimeError("No function with entry point 0x%x found" % address)
        

    def __eq__(self, other):
        return self.md5 == other.md5 and \
               self.sha1 == other.sha1 and \
               self.sha256 == other.sha256 and \
               self.sha512 == other.sha512

    def __hash__(self):
        return hash(self.sha512)

    @classmethod
    def load(clazz, path):
        with open(path, "rb") as f:
            return clazz(pickle.load(f))


class Client:
    """
    Used for sending commands to one or more IDA containers over HTTP.
    """

    def __init__(self, urls):
        """
        >>> client = Client(['http://host-1:4001', 'http://host-2:4001'])
        :param urls: List of addresses of IDA containers including the published port
        """
        if isinstance(urls, str):
            urls = [urls]
        if urls is None or not any(urls):
            raise ValueError('Invalide "urls" value')
        self._urls = itertools.cycle(urls)

    def bindiff_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a BinDiff database.
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported bindiff database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/bindiff/export" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post("%s/bindiff/export" % next(self._urls), data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle, output = tempfile.mkstemp(suffix = ".BinExport")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return output
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None

    def pickle_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a pickle file. 
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported pickle database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/bindiff/export" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post("%s/pickle/export" % next(self._urls), data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle, output = tempfile.mkstemp(suffix = ".pickle")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return output
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None

    def bindiff_pickle_export(self, sample, is_64_bit = True, timeout = None):
        """
        Load a sample into IDA Pro, perform autoanalysis and export a pickle file. 
        :param sample: The sample's path
        :param is_64_bit: If the sample needs to be analyzed by the 64 bit version of IDA
        :param timeout: Timeout for the analysis in seconds
        :return: The file name of the exported pickle database. The file needs
        to be deleted by the caller. Returns None on error.
        """

        data_to_send = {
            "timeout": timeout,
            "is_64_bit": is_64_bit}
        url = "%s/bindiff_pickle/export" % next(self._urls)
        log.debug("curl -XPOST --data '%s' '%s'", json.dumps(data_to_send), url)
        response = requests.post(url, data = data_to_send, files = {os.path.basename(sample): open(sample, "rb")})
        if response.status_code == 200:
            handle_tar, path_tar = tempfile.mkstemp(suffix = ".tar.gz")
            with os.fdopen(handle_tar, "wb") as f:
                map(f.write, response.iter_content(1024))
            directory = tempfile.mkdtemp()
            subprocess.check_call(["tar", "xf", path_tar], cwd = directory)

            handle_bindiff, output_bindiff = tempfile.mkstemp(suffix = ".BinExport")
            with os.fdopen(handle_bindiff, "wb") as f:
                with open(os.path.join(directory, "output.BinExport"), "rb") as f2:
                    shutil.copyfileobj(f2, f)
            handle_pickle, output_pickle = tempfile.mkstemp(suffix = ".pickle")
            with os.fdopen(handle_pickle, "wb") as f:
                with open(os.path.join(directory, "output.pickle"), "rb") as f2:
                    shutil.copyfileobj(f2, f)
            os.unlink(path_tar)
            shutil.rmtree(directory)
            return output_bindiff, output_pickle
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None

    def bindiff_compare(self, primary, secondary, timeout = None):
        """
        Run BinDiff on the two BinDiff databases.
        :param primary: The first BinExport database
        :param secondary: The second BinExport database
        :param timeout: Timeout for the command in seconds
        :returns: The directory name of the directory with the generated data on the shared volume
        """

        url = "%s/bindiff/compare" % next(self._urls)
        log.debug("curl -XPOST --form 'timeout=%s' --form 'primary=@%s' --form 'secondary=@%s' '%s'", str(timeout), primary, secondary, url)
        response = requests.post(url, data = {"timeout": timeout}, \
                files = {"primary": open(primary, "rb"), "secondary": open(secondary, "rb")})

        if response.status_code == 200:
            handle, path = tempfile.mkstemp(suffix = ".bindiff.sqlite3")
            with os.fdopen(handle, "wb") as f:
                map(f.write, response.iter_content(1024))
            return path
        else:
            log.error("Bindiff server responded with status code %d: %s", response.status_code, response.content)
            return None
