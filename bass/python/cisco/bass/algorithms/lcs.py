#!/usr/bin/env python2.7
# Taken from https://github.com/wuzhigang05/Dynamic-Programming-Linear-Space/blob/master/AlignTwoStringInLinearSpace.py
# Licensed under BSD 3-clause license
import logging
from ctypes import CDLL, c_char_p, c_size_t, POINTER, c_int, create_string_buffer, byref
from pkg_resources import resource_filename

log = logging.getLogger("cisco.bass.algorithms.lcs")


# Initialize ctypes library
_lib = CDLL(resource_filename("cisco.bass.algorithms", "_lcs.so"))
if not _lib:
    raise RuntimeError("Error loading shared library _lcs.so in cisco.bass.algorithms.lcs")
_lib.hirschberg_lcs.argtypes = [c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)]
_lib.hirschberg_lcs.restype = c_int
_lib.hamming_klcs_c.argtypes = [POINTER(c_char_p), POINTER(c_size_t), c_size_t, c_char_p, POINTER(c_size_t)]
_lib.hamming_klcs_c.restype = c_int
    

def lcs(s, t):
    """
        Calculate the longest common subsequence between two sequences in O(min(len(x), len(y))) space and O(len(x) * len(y)) time.
        Implemented in C++.
        Since only one instance from the set of longest common subsequences is returned,
        the algorithm has the unpleasing property of not being commutative (i.e., changing
        the input vectors changes the result).
        :see: https://en.wikipedia.org/wiki/Hirschberg%27s_algorithm
        :param x: First input sequence.
        :param y: Second input sequence.
        :return: LCS(x, y)
    """
    result = create_string_buffer("\0" * min(len(s), len(t)))
    result_len = c_size_t(len(result))
    if isinstance(s, list):
        s = "".join(s)
    if isinstance(t, list):
        t = "".join(t)
    ret = _lib.hirschberg_lcs(s, len(s), t, len(t), result, byref(result_len))
    if ret == 0:
        return result[:result_len.value]
    else:
        raise RuntimeError("lcs returned error code %d" % ret)

def hamming_klcs(seqs):
    """
        Implementation of k-LCS as described in Christian Blichmann's thesis "Automatisierte Signaturgenerierung fuer Malware-Staemme" on page 52.
        This algorithm will not forcibly find THE longest common subsequence among all sequences, as the subsequence returned by the 2-LCS algorithm
        might not be the optimal one from the set of longest common subsequences.
        :see: https://static.googleusercontent.com/media/www.zynamics.com/en//downloads/blichmann-christian--diplomarbeit--final.pdf
        :param seqs: List of sequences
        :return: A shared subsequence between the input sequences. Not necessarily the longest one, and only one of several that might exist.
    """
    c_seqs_type = c_char_p * len(seqs)
    c_seqs = c_seqs_type()
    c_seqs[:] = seqs
    c_lens_type = c_size_t * len(seqs)
    c_lens = c_lens_type()
    c_lens[:] = [len(seq) for seq in seqs]
    result = create_string_buffer("\0" * min(len(seq) for seq in seqs))
    result_len = c_size_t(len(result))
    ret = _lib.hamming_klcs_c(c_seqs, c_lens, len(seqs), result, byref(result_len))
    if ret == 0:
        return result[:result_len.value]
    else:
        raise RuntimeError("lcs returned error code %d" % ret)


