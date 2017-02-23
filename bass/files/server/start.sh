#!/bin/sh

trap '(kill -TERM $cron $clamd $python; exit 0)' 1 15

/usr/sbin/cron -f &
cron=$!
/usr/sbin/clamd &
clamd=$!
#/usr/bin/freshclam &
#freshclam=$!
printf "Waiting for clamd to start "
while ! [ -S /var/run/clamav/clamd.ctl ]
do
    printf "."
    sleep 1
done
printf "\n"
/usr/bin/python server.py &
python=$!

wait $cron $clamd $python
