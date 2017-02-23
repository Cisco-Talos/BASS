import json
import sys
import logging
import random
import string
import re
from requests import Session

log = logging.getLogger("cisco.bass")

def _translate_db(db, name = None):
    return {
        "name": name if name is not None else ("random_%s" % "".join(random.choice(string.letters + string.digits) for _ in range(32))),
        "architecture": {
            "type": db.architecture_name,
            "size": {32: "b32", 64: "b64"}[db.architecture_bits],
            "endian": {"little": "le", "big": "be"}[db.architecture_endianness],
        },
        "functions": [{
            "name": func.name,
            "id": func.entry_point,
            "call": func.calls,
            "api": func.apis,
            "sea": func.entry_point,
            "see": max(chunk.end for chunk in func.chunks),
            "blocks": [{
                "id": bb.id,
                "sea": bb.start + (1 if bb.thumb else 0),
                "eea": bb.end,
                "name": bb.name,
                "bytes": "".join("%02x" % ord(x) for x in bb.bytes),
                "dat": dict((hd.address, "".join("%02x" % ord(y) for y in db.get_bytes(hd.data_refs[0], hd.data_refs[0] + 8))) \
                        for hd in bb.code_heads if len(hd.data_refs) >= 1 and db.get_bytes(hd.data_refs[0], hd.data_refs[0] + 8) is not None),
                "src": [("0x%X" % hd.address, hd.disassembly.split()[0]) + tuple(op["opnd"] for op in hd.data["operands"]) \
                        for hd in bb.code_heads if hd.mnemonic != ""],
                "call": [succ.id for succ in bb.successors]} for bb in func.basic_blocks],
        } for func in db.functions],
    }

class Client():
    """
        A client to speak to the Kam1n0 server.
    """

    def __init__(self, url, user, password):
        """
            Create a session with the server.
            :param user: User name
            :param password: Password
            :except: Raises RuntimeError if server replies with an error code.
        """
        self.url = url
        self.session = Session()
        self._login(user, password)

    def _login(self, user, password):
        response = self.session.post("%s/j_security_check" % self.url, data = {"j_username": user, "j_password": password})
        if response.status_code != 200:
            log.error("Error logging into Kam1n0 service - response code %d, message %s", response.status_code, response.content)
            raise RuntimeError("Cannot log in to Kam1n0 server - response code %d" % response.status_code)

    def index_functions(self, db, binary_name):
        """
            Index functions.
            :param db: Database in our pickle format.
            :param binary_name: Name of the binary. Probably a SHA256 would be most meaningful.
            :except: Raises RuntimError on unexpected server reply.
        """
        response = self.session.post("%s/admin/BinarySurrogateIndex" % self.url, data = {"func": json.dumps(_translate_db(db, binary_name))})
        self._check_response(response)

    def query_function(self, db, threshold = 0.01, topk = 10):
        """
            Query function.
            :param db: Database in our pickle format.
            :param threshold: Threshold for identifying similar functions.
                Values between 0.0 and 1.0 seem reasonable.
            :param topk: Number of matches to return.
            :returns: A list of matches
            :except: Raises RuntimError on unexpected server reply.
        """
        response = self.session.post("%s/FunctionSurrogateClone" % self.url, data = \
                {"func": json.dumps(_translate_db(db)), "thld": threshold, "topk": topk})
        self._check_response(response)
        return response.json()

    def query_binary(self, db, threshold = 0.01, topk = 10):
        """This doesn't work currently."""
        raise NotImplementedError("Function is not working as it should")
        response = self.session.post("%s/BinarySurrogateComposition" % self.url, data = \
            {"file": json.dumps(_translate_db(db)), "threshold": threshold, "topk": topk})
        if response.status_code != 200:
            log.error("Got server reply %d: %s", response.status_code, response.content)
            raise RuntimeError("Got server error reply %d" % response.status_code)
        else:
            return response.json()

    def get_function(self, function_id):
        """This doesn't work currently."""
        raise NotImplementedError("Function is not working as it should")
        response = self.session.get("%s/FunctionFlow" % self.url, params = {"fid": function_id})
        self._check_response(response)
        return response.json()

    def list_binaries(self):
        """
            List all binaries indexed on the server.
            :returns: A list of dictionaries with 'name' and 'numOfFunctions' keys.
        """
        response = self.session.get("%s/admin/BinaryList" % self.url)
        self._check_response(response)
        return response.json()

    def delete_binary(self, binary):
        """
            Delete a binary from the server.
            :param binary: The binary's name as returned by list_binaries.
        """
        response = self.session.post("%s/admin/BinaryDrop" % self.url, data = {"bid": binary})
        self._check_response(response)


    def db_info(self):
        """
            Get database information.
        """
        response = self.session.get("%s/admin/InfoDB" % self.url)
        self._check_response(response)
        return response.json()

    def db_mode(self):
        """
            Get the current database mode (symbolic/metapc/...)
        """
        response = self.session.get("%s/CurrentMode" % self.url)
        self._check_response(response)
        return response.content

    def user_name(self):
        """
            Get the user name of the current user.
        """
        response = self.session.get("%s/UserName" % self.url)
        self._check_response(response)
        return response.content

    def system_info(self):
        """
            Get system information.
        """
        response = self.session.get("%s/admin/InfoSystem" % self.url)
        self._check_response(response)
        return response.json()




    def _check_response(self, response):
        if response.status_code != 200:
            log.error("Got server reply %d: %s", response.status_code, response.content)
            raise RuntimeError("Got server error reply %d" % response.status_code)
        elif response.content.startswith("<!DOCTYPE html>") and "j_password" in response.content:
            log.error("Not logged in: %s", response.content)
            raise RuntimeError("Not logged in to Kam1n0 server")
        elif response.content.startswith("E:"):
            log.error("Error response from server: %s", response.content[2:])
            raise RuntimeError("Error response from server: %s" % response.content[2:])
