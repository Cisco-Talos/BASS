import hashlib
from functools import partial
import re

RE_SHA512 = re.compile("^[A-Fa-f0-9]{128}$")
RE_SHA256 = re.compile("^[A-Fa-f0-9]{64}$")
RE_SHA1 = re.compile("^[A-Fa-f0-9]{40}$")
RE_MD5 = re.compile("^[A-Fa-f0-9]{32}$")

BLOCK_SIZE = 4096

def file_sha256(path):
    """Get the hex digest of the given file"""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        map(sha256.update, iter(partial(f.read, BLOCK_SIZE), ""))
    return sha256.hexdigest()
        
def is_sha512(hash_):
    """Test if hash_ is a SHA512 hash."""
    return RE_SHA512.match(hash_) is not None

def is_sha256(hash_):
    """Test if hash_ is a SHA256 hash."""
    return RE_SHA256.match(hash_) is not None

def is_sha1(hash_):
    """Test if hash_ is a SHA1 hash."""
    return RE_SHA1.match(hash_) is not None

def is_md5(hash_):
    """Test if hash_ is an MD5 hash."""
    return RE_MD5.match(hash_) is not None
