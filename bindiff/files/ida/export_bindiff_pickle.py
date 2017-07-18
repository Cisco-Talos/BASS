"""
    Do IDA autoanalysis and dump bindiff database file
    as well as a pickle file with all the relevant info from the
    IDB for later processing with python.
    Call me with
    `idaw.exe -S"export_bindiff.py test.BinDiff" -A -B .\sample`
    to generate the BinDiff database _test.BinDiff_ from file _sample_.
"""
import sys
import os
import argparse
import pickle
import hashlib

def get_api_calls(func):
    func_flags = GetFunctionFlags(func)
    if func_flags & FUNC_LIB or func_flags & FUNC_THUNK:
        return

    for inst in filter(lambda x: idaapi.is_call_insn(x), FuncItems(func)):
        try:
            api_address = CodeRefsFrom(inst, 0).next()
            api_flags = GetFunctionFlags(api_address)
            if api_flags & FUNC_LIB or api_flags & FUNC_THUNK:
                yield {"address": api_address, "name": NameEx(0, api_address)}
        except StopIteration:
            pass

def get_many_bytes(start, length):
    BLOCKSIZE = 512
    blocks = [(s, e - s) for s, e in zip(range(start, start + length)[:-1], range(start, start + length)[1:])]
    data = []
    for s, l in blocks:
        d = GetManyBytes(s, l)
        if d is None:
            d = []
            for i in range(s, s + l):
                v = chr(Byte(i))
                if v is not None:
                    d.append(v)
                else:
                    break
            d = "".join(d)
        data.append(d)
    return "".join(data)

def pickle_database(path):
    info = idaapi.get_inf_structure()
    database = {
        "segments": [],
        "architecture" : {
            "name": info.procName,
            "bits": 32 if info.is_32bit() else (64 if info.is_64bit() else None),
            "endian": "big" if idaapi.cvar.inf.mf else "little",
        },
        "entry_points": [{"index": idx, "ordinal": ordnl, "address": ea, "name": name} for \
                idx, ordnl, ea, name in Entries()],
        "functions": [],
        "filename": GetInputFile(),
        "sha512": hashlib.sha512(open(GetInputFilePath(), "rb").read()).hexdigest(),
        "sha256": hashlib.sha256(open(GetInputFilePath(), "rb").read()).hexdigest(),
        "sha1": hashlib.sha1(open(GetInputFilePath(), "rb").read()).hexdigest(),
        "md5": GetInputFileMD5(),
    }
    for seg in Segments():
        heads = []
        for head in Heads(SegStart(seg), SegEnd(seg)):
            if isCode(GetFlags(head)):
                operands = []
                for i in range(5):
                    if GetOpnd(head, i) == "":
                        break
                    operands.append({
                        "type": GetOpType(head, i),
                        "opnd": GetOpnd(head, i),
                        "value": GetOperandValue(head, i)})
                hd = {
                    "type": "code",
                    "size": ItemSize(head),
                    "mnem": GetMnem(head),
                    "disasm": GetDisasm(head),
                    "operands": operands,
                    "is_call": idaapi.is_call_insn(head),
                    "data_refs": list(DataRefsFrom(head)),
                    "flow_refs": list(set(CodeRefsFrom(head, True)) - set(CodeRefsFrom(head, False))),
                    "code_refs": list(CodeRefsFrom(head, False))}
                if NameEx(BADADDR, head) != "":
                    hd["name"] = NameEx(BADADDR, head)
                if database["architecture"]["name"] == "arm":
                    hd["thumb"] = GetReg(head, 'T') != 0
                #for dref in DataRefsFrom(head):
                #    dhead = {
                #        "type": "data",
                #        "size": ItemSize(dref)}
                #    if NameEx(BADADDR, dref) != "":
                #        dhead["name"] = NameEx(BADADDR, dref)
                #    heads.append((dref, dhead))
                heads.append((head, hd))
        database["segments"].append({
            "virtual_address": SegStart(seg),
            "virtual_size": SegEnd(seg) - SegStart(seg),
            "file_offset": idaapi.get_fileregion_offset(SegStart(seg)),
            "data": get_many_bytes(SegStart(seg), SegEnd(seg) - SegStart(seg)),
            "code_heads": dict(heads)})

    database["strings"] = [{
        "address": x.ea, 
        "data": str(x),
        "encoding_size": 1 if x.is_1_byte_encoding() else (2 if x.is_2_byte_encoding() else (4 if x.is_4_byte_encoding() else None)),
        "type": x.type} for x in Strings()]

    database["functions"] = [{
        "entry_point": x,
        "name": GetFunctionName(x),
        "chunks": [{"start": start, 
                    "end": end, 
                    "code_heads": [h for h in Heads(start, end) if isCode(GetFlags(h))]} for (start, end) in Chunks(x)],
        "basic_blocks": [{"start": bb.startEA, 
                          "end": bb.endEA, 
                          "id": bb.id,
                          "code_heads": [h for h in Heads(bb.startEA, bb.endEA) if isCode(GetFlags(h))],
                          "successors": [succ.id for succ in bb.succs()]} \
                            for bb in idaapi.FlowChart(idaapi.get_func(x))],
        "called_from": list(CodeRefsTo(x, False)),
        "api_calls": list(get_api_calls(x)),
        "is_library_function": bool(GetFunctionFlags(x) & idaapi.FUNC_LIB or GetFunctionFlags(x) & idaapi.FUNC_THUNK)} \
            for x in Functions()]

    with open(path, "wb") as file_:
        pickle.dump(database, file_, 2)

def binexport_database(path):
    idc.Eval("BinExport2Diff9(\"%s\")" % path)

def main(args):
    binexport_database(args.bindiff_output)
    pickle_database(args.pickle_output)

    return 0

def parse_args():
    parser = argparse.ArgumentParser(description = "IDA Pro script: Dump bindiff database file")
    parser.add_argument("bindiff_output", type = str, help = "Output BinDiff database file")
    parser.add_argument("pickle_output", type = str, help = "Output pickle database file")
    args = parser.parse_args(idc.ARGV[1:])

    return args

Wait()
ret = main(parse_args())
Exit(ret)
