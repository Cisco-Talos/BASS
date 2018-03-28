from collections import defaultdict
import pickle

class BasicBlock(object):
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

    def __eq__(self, other):
        return self.start == other.start and \
               self.end == other.end and \
               self.bytes == other.bytes

    def __hash__(self):
        return self.start ^ self.end


class Chunk(object):
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

class Function(object):
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
    def entry_basic_block(self):
        for bb in self.basic_blocks:
            if bb.start == self.entry_point:
                return bb

        return None

    @property
    def apis(self):
        return [x["name"] for x in self.data["api_calls"]]

    @property
    def is_library_function(self):
        return self.data["is_library_function"]

class Segment(object):
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

class Head(object):
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

class Database(object):
    def __init__(self, data):
        self.data = data
        self.callees = defaultdict(set)
        for func in self.data["functions"]:
            for call in func["called_from"]:
                self.callees[call].add(func["entry_point"])

    def get_bytes(self, start, end):
        for seg in self.segments:
            if seg.start <= start and end <= seg.end:
                return seg.get_bytes(start, end)
        return None

    @property
    def ep_to_function(self):
        return dict((x["entry_point"], x) for x in self.data["functions"])
        

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
