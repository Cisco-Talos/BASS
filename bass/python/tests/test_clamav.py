from cisco.bass.algorithms import ndb_from_common_sequence

def test_clamav_ndb_from_common_sequence():
    a = "aaxxbbyycc"
    b = "aaggbbhhcc"
    common = "aabbcc"
    ndb = ndb_from_common_sequence([a, b], common)
    assert(ndb == "6161*6262*6363")
