![BASS logo](/documentation/images/BASS_logo_fullcolor_onwhite.png)

BASS
====
BASS (pronounced “bæs”) is a framework designed to automatically generate
antivirus signatures from samples belonging to previously generated malware
clusters. It is meant to reduce resource usage of ClamAV by producing more
pattern-based signatures as opposed to hash-based signatures, and to alleviate
the workload of analysts who write pattern-based signatures. The framework is
easily scalable thanks to Docker.
 
Please note that this framework is still considered in the Alpha stage and as a
result, it will have some rough edges. As this tool is open source and actively
maintained by us, we gladly welcome any feedback from the community on
improving the functionality of BASS.

Installation
------------

### Prerequisites
You need Docker 
([installation instructions](https://docs.docker.com/engine/installation/#docker-cloud)) 
and docker-compose ([installation instructions](https://docs.docker.com/compose/install/))
installed. Even if your distribution has packages for those, we recommend you
to install them as described in the installation instructions to have the
newest versions available. Parts of our software might not work with old
versions of docker and docker-compose.

Further, the client to speak to the docker cluster needs the python _requests_
package installed. This can for example be done with `pip install requests` if
you use python's pip package manager.

To build the containers, you need to export some environment variables:
```
IDA_BINARY=... #Make this variable point to your IDA Pro installation binary
IDA_PASSWORD=... #Set this variable to your IDA Pro installation password
IDA_WEB_PASSWORD=... #Set this variable to your IDA Pro restriced web password
cp ${IDA_BINARY} ida7/ida.run
export IDA_PASSWORD
export IDA_WEB_PASSWORD
```

You need to set the variables whenever you open a new shell that you want to
use to build or run BASS.

### Building the containers
Normally it should be enough to run `docker-compose build` in the repository
root directory to build BASS' containers.



Running BASS
------------

If you have a VirusTotal key, export it in the shell where you run the docker
(e.g., `export VIRUSTOTAL_API_KEY=xxx` in bash).
Run `docker-compose up` in the project's root directory to start BASS.

Then use the client in client/client.py to submit samples and get the resulting
signature.

For example, run `python ./client/client.py sample1 sample2 sample3`
to generate a signature for the cluster consisting of binaries _sample1_, _sample2_
and _sample3_.


Debugging
---------

The job object has an _exception_ and _exception\_trace_ property which contain
information about a raised exception if the job finished with an error status.

Debug logs may be found in the docker volume mounted to _/tmp/bass\_logs_. In
particular it might be helpful to track progress in the most recent log file
via `tail -f $( ls /tmp/bass_logs/*.log | tail -n 1 )`.

Hacking
-------

The client is contained in _client/_.

The folders _bass/_, _bindiff/_ and _kamino/_ contain the docker containers for
the specific tools. 

Python APIs for the REST interface of kamino and bindiff are in
_./bass/python/cisco/bass/docker/_. 

The k-LCS algorithm is implemented as a C library (source in
_./bass/python/src/\_lcs.cpp_) which is interfaced with ctypes.

If you are looking for a starting point to the signature generation process,
have a look at _./bass/python/cisco/bass/core.py_.
