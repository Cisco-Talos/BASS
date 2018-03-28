#!/usr/bin/env python

# :copyright: Copyright (C) 2017 Cisco Systems 
# :author: Jonas Zaddach <jzaddach@cisco.com>

import sys
import os
import argparse
from flask import Flask, request, jsonify, make_response, send_file
from sqlalchemy import Column, ForeignKey, BigInteger, String, DateTime
from sqlalchemy import Integer, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm.exc import NoResultFound
import hashlib
import datetime
import time
import hashlib
import json
import pickle
import binascii

from cisco.bass.util import is_md5, is_sha1, is_sha256, is_sha512
from cisco.bass.util import file_sha256
from cisco.bass.binary_database import Database

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

Base = declarative_base()
Session = None

class Architecture(Base):
    __tablename__ = "architectures"
    
    id = Column(BigInteger(), primary_key = True)
    name = Column(String(32))
    bits = Column(Integer())
    little_endian = Column(Boolean())

class Function(Base):
    __tablename__ = "functions"

    id = Column(BigInteger(), primary_key = True)
    executable = Column(String(64)) #SHA256 of the executable this function was first taken from
    entry_point = Column(BigInteger()) #Entry point in the binary where it was taken from
    raw_sha256 = Column(String(64)) #SHA256 of the raw function bytes
    mnem_sha256 = Column(String(64)) #SHA256 of the concatenated string of mnemonics
    data = Column(Text()) #JSON-encoded function data
    architecture = Column(BigInteger(), ForeignKey("architectures.id"), nullable = False)
    instructions = Column(BigInteger()) #Number of instruction in the function
    basic_blocks = Column(BigInteger()) #Number of basic blocks in the function
    transitions = Column(BigInteger()) #Number of BB transitions in the function
    loops = Column(BigInteger()) #Number of loops inside the function
    size = Column(BigInteger()) #Function body size in bytes

def _function_calculate_raw_sha256(func):
    """Calculate the hash over the raw function bytes"""
    hashsum = hashlib.sha256()
    for chunk in func.chunks:
        hashsum.update(chunk.bytes)
    return hashsum.hexdigest()

def _function_calculate_mnem_sha256(func):
    """Calculate the hash over the function's opcode mnemonics"""
    hashsum = hashlib.sha256()
    for bb in func.basic_blocks:
        for head in bb.code_heads:
            hashsum.update(head.mnemonic)
    return hashsum.hexdigest()

def _function_count_instructions(func):
    """Count the instructions in a function"""
    return sum(1 for bb in func.basic_blocks for _ in bb.code_heads)

def _function_get_size(func):
    """Get the size of the function bytes"""
    return sum(len(chunk.bytes) for chunk in func.chunks)

def _function_get_json(func):
    """Return the function in standalone JSON"""
    data = dict(func.data)
    data["chunks"] = []
    for chunk in func.chunks:
        c = dict(chunk.data)
        c["bytes"] = binascii.hexlify(chunk.bytes)
        data["chunks"].append(c)

    return data

def _function_count_basic_blocks(func):
    """count the basic blocks in a function"""
    return sum(1 for _ in func.basic_blocks)

def _function_count_transitions(func):
    """Count the number of transitions between basic blocks in a function"""
    return sum(1 for bb in func.basic_blocks for _ in bb.successors)

def _function_count_loops(func):
    explored = set()
    to_explore = [func.entry_basic_block]
    loop_count = 0
    
    while to_explore:
        bb = to_explore.pop()
        if bb in explored:
            loop_count += 1
            continue

        for succ in bb.successors:
            to_explore.append(succ)

        explored.add(bb)

    return loop_count

@app.route('/function/<fid>', methods = ['GET'])
def function_get(fid):
    global Session
    session = Session()
    try:
        function = session.query(Function).filter(Function.id == fid).one()
        return make_response(jsonify(**json.loads(function.data)), 200)
    except NoResultFound:
        return make_response(jsonify(message = "Function not found"), 404)


@app.route('/function/find/raw', methods = ['POST'])
def function_raw_hash_get():
    global Session
    session = Session()
    filename, file_ = request.files.items()[0]
    db = Database(pickle.load(file_))

    arch_name = db.architecture_name
    if arch_name == "metapc":
        arch_name = "x86"
    try:
        arch = session.query(Architecture).filter(Architecture.name == arch_name and \
                Architecture.bits == db.architecture_bits and \
                Architecture.little_endian == db.architecture_endianness == "little").one()
    except NoResultFound:
        return make_response(jsonify(message = "Architecture not found"), 404)
    
    try:
        func = next(db.functions)
    except StopIteration:
        return make_response(jsonify(message = "No function found in database"), 500)

    raw_hash = _function_calculate_raw_sha256(func)
    size = _function_get_size(func)

    try:
        function = session.query(Function).filter(Function.raw_sha256 == raw_hash and \
                Function.size == size and \
                Function.arch == arch.id).one()
        return make_response(jsonify(**json.loads(function.data)), 200)
    except NoResultFound:
        return make_response(jsonify(message = "Function not found"), 404)

@app.route('/function/find/mnem', methods = ['POST'])
def function_mnem_hash_get():
    global Session
    session = Session()
    filename, file_ = request.files.items()[0]
    db = Database(pickle.load(file_))

    arch_name = db.architecture_name
    if arch_name == "metapc":
        arch_name = "x86"
    try:
        arch = session.query(Architecture).filter(Architecture.name == arch_name and \
                Architecture.bits == db.architecture_bits and \
                Architecture.little_endian == db.architecture_endianness == "little").one()
    except NoResultFound:
        return make_response(jsonify(message = "Architecture not found"), 404)
    
    try:
        func = next(db.functions)
    except StopIteration:
        return make_response(jsonify(message = "No function found in database"), 500)

    mnem_hash = _function_calculate_mnem_sha256(func)

    try:
        function = session.query(Function).filter(Function.mnem_sha256 == mnem_hash and \
                Function.arch == arch.id).one()
        return make_response(jsonify(**json.loads(function.data)), 200)
    except NoResultFound:
        return make_response(jsonify(message = "Function not found"), 404)


@app.route('/function', methods = ['POST'])
def function_add():
    global Session

    session = Session()
    filename, file_ = request.files.items()[0]
    db = Database(pickle.load(file_))
    arch_name = db.architecture_name
    if arch_name == "metapc":
        arch_name = "x86"
    # Get the architecture, if it already exists
    try:
        arch = session.query(Architecture).filter(Architecture.name == arch_name and \
                Architecture.bits == db.architecture_bits and \
                Architecture.little_endian == db.architecture_endianness == "little").one()
    except NoResultFound:
        arch = Architecture(name = arch_name, 
                            bits = db.architecture_bits, 
                            little_endian = db.architecture_endianness == "little")
        session.add(arch)

    for func in db.functions:
        raw_hash = _function_calculate_raw_sha256(func)
        size = _function_get_size(func)

        try:
            function = session.query(Function).filter(Function.raw_sha256 == raw_hash and \
                    Function.size == size and \
                    Function.arch == arch.id).one()
        except NoResultFound:
            mnem_hash = _function_calculate_mnem_sha256(func)
            instrs = _function_count_instructions(func)
            bbs = _function_count_basic_blocks(func)
            loops = _function_count_loops(func)
            trans = _function_count_transitions(func)
            func_json = _function_get_json(func)

            function = Function(
                    raw_sha256 = raw_hash,
                    size = size,
                    mnem_sha256 = mnem_hash,
                    executable = db.sha256,
                    entry_point = func.entry_point,
                    data = json.dumps(func_json),
                    architecture = arch.id,
                    basic_blocks = bbs,
                    transitions = trans,
                    loops = loops)
            session.add(function)

    session.commit()

    return make_response("", 200)


        
    
def main(args, env):
    global Session

    if args.verbose >= 1:
        app.config['DEBUG'] = True
    sys.stderr.write("connecting to DB server {:s}\n".format(args.db))
    connection_succeeded = False
    while not connection_succeeded:
        try:
            engine = create_engine(args.db)
            Session = sessionmaker(bind = engine)
            Base.metadata.create_all(engine)
            sys.stderr.write("connection succeeded!\n")
            connection_succeeded = True
            app.run(debug = args.verbose >= 1, host = "0.0.0.0", port = 80)
        except OperationalError as err:
            if "Connection refused" in str(err):
                connection_succeeded = False
                time.sleep(10)
            else:
                raise

def parse_args():
    parser = argparse.ArgumentParser(description = "Function database server")
    parser.add_argument("-v", "--verbose", action = "count", default = 0, help = "Increase verbosity")
    parser.add_argument("--db", type = str, default = os.environ.get("DATABASE", None), help = "Database URL to connect to")
    args = parser.parse_args()

    return args

if __name__ == "__main__":
    result = main(parse_args(), os.environ)
    if result is not None:
        sys.exit(result)
