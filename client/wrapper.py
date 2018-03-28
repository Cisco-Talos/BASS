import os
import sys
import random
import subprocess
from itertools import combinations


# from 0 to 100 (%)
t_coverage = 30
# max iteration, then quit.
t_max_iteration = 20
# group size
group_size = 5


def fullpath_listdir(directory):
    return [os.path.join(directory, f) for f in os.listdir(directory)]

def add_group(group, processed):
    for g in group:
        if g not in processed:
            processed.append(g)

def check_group(group, processed):
    counter = 0
    for g in group:
        if g in processed:
            counter += 1
    if (float(float(counter)/float(len(group)))*100) > 50:
        return False
    return True


def main():
    if len(sys.argv) != 3:
        print "[-] Usage: %s %s %s" % (sys.argv[0], "<SAMPLES_DIR>", "<NDB_DIR>")
        sys.exit(1)

    if not os.path.exists(sys.argv[1]):
        print "\t [!] Directory does not exist. Please provide a valid path."
        sys.exit(1)

    if not os.path.exists(sys.argv[2]):
        print "\t [!] Directory does not exist. Please create the directory first."
        sys.exit(1)

    possibilities = list(combinations(fullpath_listdir(sys.argv[1]), group_size))
    iteration_counter = 0
    max_hits = 0
    best_signature = ""
    files = len(os.listdir(sys.argv[1]))
    
    processed = []
    for counter in xrange(0, t_max_iteration):
        group = random.choice(possibilities)
        print ":: Group %d" % counter

        if not check_group(group, processed):
            print "\t [!] Skip this group - cluster threshold."
            continue
        
        add_group(group, processed)
        mini_cluster = "%s" % ",".join(group)
        print "\t %s" % mini_cluster
        ndb_name = "attempt%d.ndb" % counter
        ndb_path = os.path.join(sys.argv[2], ndb_name)
        ret = subprocess.Popen(["python", "client.py", mini_cluster, "--output", ndb_path], stdout = subprocess.PIPE)
        output = ret.communicate()[0]
        error = 0
        for line in output.split("\n"):
            if line.startswith("{"):
                if "Cannot find" in line:
                    error = 1
        # First check
        if error == 1:
            print "\t [!] Signature not generated - Bindiff cannot find common functions"
            print output
            continue
        
        # Another check 
        if not os.path.exists(ndb_path):
            print "\t [!] Signature not generated"
            print output
            continue
        
        print "\t:: Running ClamAV..."
        ret = subprocess.Popen(["clamscan", "-i", "-d", ndb_path, sys.argv[1]], stdout = subprocess.PIPE)
        output = ret.communicate()[0]
        
        for line in output.split("\n"):
            l = line.strip()
            if "Infected" in l:
                hits = int(l.split(":")[1])
                print "\t:: Infected files: %d" % hits
                ratio = float(float(hits)/float(files))*100
                print "\t:: Coverage: %f%%" % ratio
                # Find max
                if hits > max_hits: 
                    max_hits = hits
                    best_signature = ndb_path
                break
        
        if ratio >= t_coverage:
            print "[!] Signature found - See: %s" % ndb_path
            break

    print "[!] Max hits: %d" % max_hits
    print "[!] Best signature: %s" % best_signature


main()
