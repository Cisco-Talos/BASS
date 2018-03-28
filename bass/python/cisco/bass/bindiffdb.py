import sqlite3

class Binary():
    '''
    This class contains the information extracted from 
    the bindiff sqlite3 database regarding a single binary.
    '''
    def __init__(self, dbconn, number):
        self.number = number
        self._fields = {}
        self.dbconn = dbconn

    def get_functions(self):
        return self._get_field("select functions from file where id = %d" % self.number)

    def get_libfunctions(self):
        return self._get_field("select libfunctions from file where id = %d" % self.number)

    def get_calls(self):
        return self._get_field("select calls from file where id = %d" % self.number)

    def get_basicblocks(self):
        return self._get_field("select basicblocks from file where id = %d" % self.number)

    def get_libbasicblocks(self):
        return self._get_field("select libbasicblocks from file where id = %d" % self.number)

    def get_edges(self):
        return self._get_field("select edges from file where id = %d" % self.number)

    def get_libedges(self):
        return self._get_field("select libedges from file where id = %d" % self.number)

    def get_instructions(self):
        return self._get_field("select instructions from file where id = %d" % self.number)

    def get_sha1(self):
        return self._get_field("select hash from file where id = %d" % self.number)

    def get_exefilename(self):
        return self._get_field("select exefilename from file where id = %d" % self.number)

    def _get_field(self, query):
        if query not in self._fields:
            c = self.dbconn.cursor()
            c.execute(query)
            self._fields[query] = c.fetchone()[0]
        return self._fields[query]


class BinDiff():
    '''
    This class contains information extracted from 
    the bindiff sqlite3 database regarding the diffing 
    operation.
    '''
    def __init__(self, filename):
        self.filename = filename
        self.similar_functions = []
        self.filename = filename
        self.connect()

    def connect(self):
        self.dbconn = sqlite3.connect(self.filename)

    def _get_field(self, query):
        if query not in self._fields:
            c = self.dbconn.cursor()
            c.execute(query)
            self._fields[query] = c.fetchone()[0]
        return self._fields[query]


    def get_version(self):
        return self._get_field("select version from metadata")

    def get_similarity(self):
        return self._get_field("select similarity from metadata")

    def get_confidence(self):
        return self._get_field("select confidence from metadata")

    def get_binary(self, index):
        assert(index >= 1 and index <= 2)
        return Binary(self.dbconn, index)

    def get_similar_functions(self, 
                              min_similarity = 0.75,
                              max_similarity = None,
                              min_confidence = None,
                              min_instructions = 50,
                              min_bbs = None,
                              min_edges = None,
                              limit = 5):
        """
            Get similar functions.
            Any argument except limit can be set to 'None' to ignore it.
            :param min_similarity: Minimum similarity. Should be between 
                 0 and 1. Default is 0.75.
            :param max_similarity: Maximum similarity. Should be between
                 0 and 1 and greater than min_similarity.
            :param min_confidence: Minimum confidence. Should be between
                 0 and 1.
            :param min_instructions: Minimum number of instructions.
                 Default is 50.
            :param min_bbs: Minimum number of basic blocks.
            :param min_edges: Minimum number of edges between basic blocks.
            :param limit: Maximum number of similar functions to get. 
                 Default is 5.
        """

        c = self.dbconn.cursor()
        conditions = []
        if min_similarity is not None:
            conditions.append("similarity >= %f" % min_similarity)
        if max_similarity is not None:
            conditions.append("similarity <= %f" % max_similarity)
        if min_confidence is not None:
            conditions.append("confidence >= %f" % min_confidence)
        if min_instructions is not None:
            conditions.append("instructions >= %d" % min_instructions)
        if min_bbs is not None:
            conditions.append("basicblocks >= %d" % min_bbs)
        if min_edges is not None:
            conditions.append("edges >= %d" % min_edges)

        columns = ["address1",
                   "address2",
                   "similarity",
                   "confidence",
                   "instructions",
                   "basicblocks",
                   "edges"]

        query = ("select %s from " + \
                "function where %s order by similarity desc, confidence desc limit %d") % \
                    (", ".join(columns),
                    " and ".join(conditions),
                    limit)
        c.execute(query)
        return [dict(zip(columns, x)) for x in c.fetchall()]
