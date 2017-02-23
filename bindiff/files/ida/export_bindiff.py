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

def binexport_database(path):
    idc.Eval("BinExport2Diff8(\"%s\")" % path)

def main(args):
    binexport_database(args.bindiff_output)

    return 0

def parse_args():
    parser = argparse.ArgumentParser(description = "IDA Pro script: Dump bindiff database file")
    parser.add_argument("bindiff_output", type = str, help = "Output BinDiff database file")
    args = parser.parse_args(idc.ARGV[1:])

    return args

Wait()
ret = main(parse_args())
Exit(ret)
