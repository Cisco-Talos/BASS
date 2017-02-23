from binascii import hexlify
import logging

log = logging.getLogger("cisco.bass.algorithms.clamav")

class Wildcard():
    def __str__(self):
        return "*"

    def __repr__(self):
        return "*"

class Token():
    def __init__(self, token):
        self.token = token

    def __str__(self):
        return hexlify(self.token)

    def __repr__(self):
        return "'%s'" % self.token

def ndb_from_common_sequence(seqs, cs):
    """
        This function builds a ClamAV ndb signature from a set of sequences _seqs_ and a common sequence _cs_.
        :param seqs: Sequences on which the signature should match.
        :param cs: Common sequence which is the base of the signature.
        :return: An ndb signature.
    """
    indices = [0] * len(seqs)
    regex = []

    k = 0
    while k < len(cs):
        if k != 0:
            regex.append(Wildcard())

        indices = [seq.find(cs[k], indices[i]) for (i, seq) in enumerate(seqs)]
        regex.append(Token(cs[k]))

        k += 1
        j = 1
        while k < len(cs):
            if any(seq[indices[i] + j] != cs[k] for (i, seq) in enumerate(seqs)):
                break
            regex.append(Token(cs[k]))
            k += 1
            j += 1

    # Verify signature is ClamAV-compliant (at least two tokens following each other in between wildcards)
    clamav_regex = []
    copy = False
    for i in range(len(regex) - 1):
        if isinstance(regex[i], Token) and isinstance(regex[i + 1], Token):
            copy = True
            clamav_regex.append(regex[i])
        elif isinstance(regex[i], Token) and copy:
            clamav_regex.append(regex[i])
        elif isinstance(regex[i], Wildcard) and copy:
            clamav_regex.append(regex[i])
            copy = False
    if copy == True and isinstance(regex[-1], Token):
        clamav_regex.append(regex[-1])

    if len(clamav_regex) >= 1 and isinstance(clamav_regex[-1], Wildcard):
        del clamav_regex[-1]

    return "".join(str(x) for x in clamav_regex)
