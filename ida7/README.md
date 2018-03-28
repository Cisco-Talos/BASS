IDA Pro Server
==============

Interfacing with the server
---------------------------

### Exporting a BinExport database
```
curl -XPOST --form 'input=@/bin/ls' --form 'is_64_bit=1' --output /tmp/file.BinExport 'http://fmd-mwr01-02dev.vrt.sourcefire.com:8080/binexport'
```
Sends the binary file `/bin/ls` as 64 bit binary to the IDA server and saves
the BinExport file in `/tmp/file.BinExport`. The BinExport file is in protobuf
format.

### Exporting a pickle database
```
curl -XPOST --form 'input=@/bin/ls' --form 'is_64_bit=0' --output /tmp/file.pickle 'http://fmd-mwr01-02dev.vrt.sourcefire.com:8080/pickle'
```
Sends the binary file `/bin/ls` as 32 bit binary to the IDA server and saves
the pickle file in `/tmp/file.pickle`. The pickle file can be unpickled in
python to yield a dictionary. See [the Database
class](../bass/python/cisco/bass/docker/bindiff.py#L181) on how to easily
access this pickle file.

### Exporting both BinExport and pickle
```
curl -XPOST --form 'input=@/bin/ls' --form 'is_64_bit=1' --output /tmp/file.tar.gz 'http://fmd-mwr01-02dev.vrt.sourcefire.com:8080/binexport_pickle'
```
Sends the file `/bin/ls` as a 64 bit binary to the IDA server and saves the
resulting .tar.gz with the BinExport file and the pickle file in
`/tmp/file.tar.gz`.

### Comparing two BinExport databases with BinDiff
```
curl -XPOST --form 'primary=@/tmp/echo.BinExport' --form 'secondary=@/tmp/ls.BinExport' --output /tmp/compare.sqlite3 'http://fmd-mwr01-02dev.vrt.sourcefire.com:8080/compare'
```
Compares the primary database `/tmp/echo.BinExport` and the secondary database
`/tmp/ls.BinExport` to each other and stores the resulting sqlite3 database in
`/tmp/compare.sqlite3`. See [the BinDiff
class](../bass/python/cisco/bass/bindiffdb.py#L51) on how to easily access the
BinDiff database.

